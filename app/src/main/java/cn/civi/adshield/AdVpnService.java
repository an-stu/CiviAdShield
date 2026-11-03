package cn.civi.adshield;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.os.*;
import android.system.*;
import cn.civi.adshield.core.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Split DNS tunnel: only the synthetic resolver address enters the TUN. */
public final class AdVpnService extends VpnService {
    public static final String STOP = "cn.civi.adshield.STOP";
    private static final String DNS = "10.111.0.2";
    private final AtomicBoolean active = new AtomicBoolean();
    private final AtomicInteger generation = new AtomicInteger();
    private final Object writeLock = new Object();
    private ParcelFileDescriptor tunnel;
    private FileOutputStream output;
    private Thread reader;
    private ThreadPoolExecutor udpWorkers, tcpWorkers;
    private TcpDnsEndpoint tcp;
    private final Set<Closeable> sockets = ConcurrentHashMap.newKeySet();

    /** stopService alone cannot close a VPN while Android still has the service bound. */
    public static void requestStop(Context context) {
        context.startService(new Intent(context, AdVpnService.class).setAction(STOP));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) { finish("已暂停，可使用 Clash Meta"); return START_NOT_STICKY; }
        final int runId;
        synchronized (writeLock) {
            if (!active.compareAndSet(false, true)) return START_NOT_STICKY;
            runId = generation.incrementAndGet();
            AppState.starting = true;
            AppState.status = "正在加载规则…";
        }
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel("protection", "广告域名拦截", NotificationManager.IMPORTANCE_LOW));
            Intent stop = new Intent(this, AdVpnService.class).setAction(STOP);
            PendingIntent stopAction = PendingIntent.getService(this, 2, stop, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            PendingIntent open = PendingIntent.getActivity(this, 1, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            Notification n = new Notification.Builder(this, "protection").setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("净屏 · 广告域名拦截").setContentText("本地过滤已开启 · 使用 Clash 前请暂停")
                .setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null, "暂停", stopAction).build()).build();
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(1, n);
            synchronized (writeLock) {
                if (!isCurrent(runId)) return START_NOT_STICKY;
                reader = new Thread(() -> runTunnel(runId), "dns-tunnel-" + runId); reader.start();
            }
        } catch (RuntimeException e) { finish(runId, "启动失败：" + e.getClass().getSimpleName()); }
        return START_NOT_STICKY;
    }
    private static ThreadPoolExecutor workers(int n, String name) {
        return new ThreadPoolExecutor(n, n, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(64), r -> {
            Thread t = new Thread(r, name); t.setDaemon(true); return t;
        }, new ThreadPoolExecutor.AbortPolicy());
    }
    private boolean isCurrent(int runId) { return active.get() && generation.get() == runId; }
    private void runTunnel(int runId) {
        try {
            RulesStore.get(this);
            if (!isCurrent(runId)) return;
            Builder b = new Builder().setSession("净屏 DNS").addAddress("10.111.0.1", 32)
                .addDnsServer(DNS).addRoute(DNS, 32).setMtu(9000).setBlocking(false)
                .allowFamily(OsConstants.AF_INET6);
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            b.setConfigureIntent(PendingIntent.getActivity(this, 3, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
            Set<String> only = AppState.prefs(this).getStringSet("dns_only_packages", Collections.emptySet());
            if (!only.isEmpty()) {
                int added = 0;
                for (String pkg : only) {
                    try {
                        android.content.pm.ApplicationInfo info = getPackageManager().getApplicationInfo(pkg, 0);
                        if (info.enabled) { b.addAllowedApplication(pkg); added++; }
                    } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {}
                }
                if (added == 0) throw new IOException("指定应用未安装或已停用，请重新选择拦截范围");
            } else {
                for (String pkg : AppState.prefs(this).getStringSet("dns_bypass_packages", Collections.emptySet())) {
                    try { b.addDisallowedApplication(pkg); } catch (android.content.pm.PackageManager.NameNotFoundException ignored) {}
                }
            }
            final ParcelFileDescriptor thisTunnel;
            final ThreadPoolExecutor thisUdpWorkers, thisTcpWorkers;
            final TcpDnsEndpoint thisTcp;
            synchronized (writeLock) {
                if (!isCurrent(runId)) return;
                thisTunnel = b.establish();
                if (thisTunnel == null) throw new IOException("VPN 授权已失效，请重新开启");
                tunnel = thisTunnel;
                output = new FileOutputStream(thisTunnel.getFileDescriptor());
                udpWorkers = thisUdpWorkers = workers(4, "dns-upstream");
                tcpWorkers = thisTcpWorkers = workers(1, "dns-tcp");
                tcp = thisTcp = new TcpDnsEndpoint(query -> resolve(query, runId), packet -> writePacket(packet, runId));
                AppState.running = true; AppState.starting = false; AppState.status = "广告域名拦截运行中";
            }
            try (FileInputStream in = new FileInputStream(thisTunnel.getFileDescriptor())) {
                byte[] buffer = new byte[32768];
                StructPollfd poll = new StructPollfd(); poll.fd = thisTunnel.getFileDescriptor(); poll.events = (short) OsConstants.POLLIN;
                while (isCurrent(runId)) {
                    int ready = Os.poll(new StructPollfd[]{poll}, 1000);
                    if (!isCurrent(runId)) break;
                    if (ready == 0) continue;
                    if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) throw new IOException("VPN 接口已关闭");
                    int n = in.read(buffer);
                    if (n <= 0) continue;
                    byte[] packet = Arrays.copyOf(buffer, n);
                    try {
                        if (n >= 20 && packet[9] == 6) thisTcpWorkers.execute(() -> {
                            try { if (isCurrent(runId)) thisTcp.accept(packet, packet.length, SystemClock.elapsedRealtime()); } catch (IOException | IllegalArgumentException ignored) {}
                        });
                        else {
                            IPv4UdpCodec.Packet p = IPv4UdpCodec.parse(packet, packet.length);
                            if (p.destinationPort != 53 || !Arrays.equals(p.destinationAddress, new byte[]{10,111,0,2})) continue;
                            // Validate before enqueue, so malformed packets cannot consume sockets.
                            DnsCodec.parseQuestion(p.payload);
                            thisUdpWorkers.execute(() -> handleUdp(p, runId));
                        }
                    } catch (IllegalArgumentException | RejectedExecutionException ignored) {}
                }
            }
        } catch (Exception e) {
            finish(runId, "拦截已停止：" + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
        }
    }
    private void handleUdp(IPv4UdpCodec.Packet p, int runId) {
        try {
            byte[] response;
            try { response = resolve(p.payload, runId); }
            catch (IOException e) { response = DnsCodec.errorResponse(p.payload, 2); }
            if (response.length > udpLimit(p.payload)) {
                response = DnsCodec.errorResponse(p.payload, 0); response[2] |= 0x02; // TC: retry on TCP.
            }
            writePacket(IPv4UdpCodec.reply(p, response), runId);
        } catch (IOException | IllegalArgumentException ignored) {}
    }
    private static int udpLimit(byte[] query) {
        DnsCodec.Question q = DnsCodec.parseQuestion(query);
        int at = q.questionEnd;
        if (query.length >= at + 11 && query[at] == 0 && (query[at+1]&255) == 0 && (query[at+2]&255) == 41)
            return Math.min(4096, Math.max(512, ((query[at+3]&255)<<8) | (query[at+4]&255)));
        return 512;
    }
    private byte[] resolve(byte[] query, int runId) throws IOException {
        if (!isCurrent(runId)) throw new IOException("VPN 已暂停");
        DnsCodec.Question q = DnsCodec.parseQuestion(query);
        if (q.questionClass == 1 && RulesStore.get(this).blocks(q.domain)) {
            AppState.blocked(this, q.domain);
            return DnsCodec.blockedResponse(query);
        }
        Network network = physicalNetwork();
        if (network == null) throw new IOException("没有可用网络");
        String primary = AppState.prefs(this).getString("upstream", "223.5.5.5");
        String[] servers = primary.equals("223.5.5.5") ? new String[]{primary, "119.29.29.29"} : new String[]{primary};
        for (String server : servers) {
            if (!isCurrent(runId)) throw new IOException("VPN 已暂停");
            try (DatagramSocket socket = new DatagramSocket()) {
                sockets.add(socket);
                try {
                    if (!isCurrent(runId)) throw new IOException("VPN 已暂停");
                    if (!protect(socket)) throw new IOException("无法保护 DNS 套接字");
                    network.bindSocket(socket);
                    socket.connect(InetAddress.getByName(server), 53);
                    socket.setSoTimeout(1800);
                    socket.send(new DatagramPacket(query, query.length));
                    long deadline = SystemClock.elapsedRealtime() + 1800;
                    while (isCurrent(runId)) {
                        int remaining = (int)(deadline - SystemClock.elapsedRealtime());
                        if (remaining <= 0) break;
                        socket.setSoTimeout(remaining);
                        byte[] data = new byte[65535]; DatagramPacket reply = new DatagramPacket(data, data.length);
                        socket.receive(reply);
                        byte[] response = Arrays.copyOf(data, reply.getLength());
                        if (!DnsCodec.isValidResponse(query, response)) continue;
                        if ((response[2] & 2) != 0) return upstreamTcp(network, server, query);
                        return response;
                    }
                } finally { sockets.remove(socket); }
            } catch (IOException ignored) { /* Try explicitly disclosed secondary resolver. */ }
        }
        throw new IOException("DNS 上游不可达");
    }
    private byte[] upstreamTcp(Network network, String server, byte[] query) throws IOException {
        try (Socket socket = new Socket()) {
            sockets.add(socket);
            try {
                if (!protect(socket)) throw new IOException("无法保护 DNS TCP");
                network.bindSocket(socket); socket.connect(new InetSocketAddress(server, 53), 2000); socket.setSoTimeout(2500);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream()); out.writeShort(query.length); out.write(query); out.flush();
                DataInputStream in = new DataInputStream(socket.getInputStream()); int length = in.readUnsignedShort();
                if (length < 12) throw new IOException("无效 DNS TCP 响应");
                byte[] response = new byte[length]; in.readFully(response);
                if (!DnsCodec.isValidResponse(query, response)) throw new IOException("DNS 响应不匹配");
                return response;
            } finally { sockets.remove(socket); }
        }
    }
    private Network physicalNetwork() {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        Network fallback = null;
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities cap = cm.getNetworkCapabilities(n);
            if (cap == null || !cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) || !cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            if (cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) && cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return n;
            if (fallback == null || cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) fallback = n;
        }
        return fallback;
    }
    private void writePacket(byte[] packet, int runId) throws IOException {
        synchronized (writeLock) { if (isCurrent(runId) && output != null) output.write(packet); }
    }
    private void finish(int runId, String status) {
        synchronized (writeLock) { if (isCurrent(runId)) finish(status); }
    }
    private void finish(String status) { AppState.status = status; shutdown(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); }
    private void shutdown() {
        final Thread stoppedReader;
        synchronized (writeLock) {
            stoppedReader = reader; reader = null;
            generation.incrementAndGet(); active.set(false); AppState.running = false; AppState.starting = false;
            for (Closeable s : sockets) { try { s.close(); } catch (IOException ignored) {} } sockets.clear();
            if (udpWorkers != null) udpWorkers.shutdownNow();
            if (tcpWorkers != null) tcpWorkers.shutdownNow();
            if (tunnel != null) { try { tunnel.close(); } catch (IOException ignored) {} tunnel=null; }
            output=null;
        }
        if (stoppedReader != null) stoppedReader.interrupt();
    }
    @Override public void onRevoke() { finish("VPN 已被系统或其他 VPN 接管，网络拦截已停止"); }
    @Override public void onDestroy() { shutdown(); super.onDestroy(); }
}
