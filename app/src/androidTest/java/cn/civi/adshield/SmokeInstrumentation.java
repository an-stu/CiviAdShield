package cn.civi.adshield;

import android.app.Instrumentation;
import android.content.*;
import android.os.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import cn.civi.adshield.core.DnsCodec;

/** Emulator-only integration runner. Grant ACTIVATE_VPN via adb before running. */
public final class SmokeInstrumentation extends Instrumentation {
    private final List<String> passed = new ArrayList<>();
    @Override public void onCreate(Bundle args) { super.onCreate(args); start(); }
    @Override public void onStart() {
        Context c=getTargetContext(); String beforeCustom="", beforeAllow="";
        Bundle result=new Bundle(); int resultCode=-1;
        try {
            beforeCustom=RulesStore.read(c,false); beforeAllow=RulesStore.read(c,true);
            startActivitySync(new Intent(c,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); waitForIdleSync();
            RulesStore.save(c,false,"probe.adshield.invalid\n"); RulesStore.save(c,true,"allowed.probe.adshield.invalid\n");
            check(RulesStore.get(c).blocks("probe.adshield.invalid"),"custom domain blocks");
            check(!RulesStore.get(c).blocks("allowed.probe.adshield.invalid"),"whitelist precedence");
            ByteArrayOutputStream exported=new ByteArrayOutputStream(); RulesStore.exportClash(c,exported);
            String yaml=exported.toString(StandardCharsets.UTF_8.name());
            check(yaml.contains("payload:") && !yaml.contains("'+.probe.adshield.invalid'"),"Clash export preserves subdomain whitelist");
            // Preauthorizing ACTIVATE_VPN still requires prepare() to select this VPN package.
            check(android.net.VpnService.prepare(c)==null,"VPN authorization prepared");
            runOnMainSync(() -> c.startForegroundService(new Intent(c,AdVpnService.class)));
            waitUntil(() -> AppState.running,10000,"VPN starts");
            // Android publishes the UID's VPN route asynchronously after establish() returns.
            android.net.ConnectivityManager cm=c.getSystemService(android.net.ConnectivityManager.class);
            waitUntil(() -> {
                android.net.NetworkCapabilities caps=cm.getNetworkCapabilities(cm.getActiveNetwork());
                return caps!=null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN);
            },10000,"VPN routes active for test process");
            byte[] q=query("probe.adshield.invalid",1);
            byte[] response=udp(q);
            boolean locallyBlocked=DnsCodec.isValidResponse(q,response) && response[7]==0 && (response[3]&15)==0;
            check(locallyBlocked,locallyBlocked?"UDP A locally blocked":"UDP A unexpected response / " + Arrays.toString(response));
            byte[] q6=query("probe.adshield.invalid",28);
            response=udp(q6);
            check(DnsCodec.isValidResponse(q6,response) && response[7]==0,"UDP AAAA locally blocked");
            try(Socket socket=new Socket()) {
                socket.connect(new InetSocketAddress("10.111.0.2",53),4000); socket.setSoTimeout(4000);
                DataOutputStream out=new DataOutputStream(socket.getOutputStream()); out.writeShort(q.length); out.write(q); out.flush();
                DataInputStream in=new DataInputStream(socket.getInputStream()); int length=in.readUnsignedShort(); byte[] tcp=new byte[length]; in.readFully(tcp);
                check(DnsCodec.isValidResponse(q,tcp) && tcp[7]==0,"TCP DNS locally blocked");
            }
            byte[] normal=query("example.com",1); byte[] answer=udp(normal);
            check(DnsCodec.isValidResponse(normal,answer) && (answer[3]&15)==0 && ((answer[6]&255)*256+(answer[7]&255))>0,"normal DNS forwarded");
            check(InetAddress.getByName("example.org")!=null,"system DNS resolution works");
            runOnMainSync(() -> AdVpnService.requestStop(c));
            waitUntil(() -> !AppState.running && !AppState.starting,5000,"VPN stops cleanly");
            for(int cycle=0;cycle<3;cycle++) {
                check(android.net.VpnService.prepare(c)==null,"restart authorization "+cycle);
                runOnMainSync(() -> c.startForegroundService(new Intent(c,AdVpnService.class)));
                waitUntil(() -> AppState.running,10000,"VPN restart "+cycle);
                Thread.sleep(1200);
                byte[] restarted=udp(q);
                check(AppState.running && DnsCodec.isValidResponse(q,restarted),"restarted tunnel survives old-reader cleanup "+cycle);
                runOnMainSync(() -> AdVpnService.requestStop(c));
                waitUntil(() -> !AppState.running && !AppState.starting,5000,"VPN repeat stop "+cycle);
            }
            result.putString("stream","\nPASS " + passed.size() + " integration checks:\n" + String.join("\n",passed)+"\n");
        } catch(Throwable e) {
            resultCode=0;
            result.putString("stream","\nFAILED after " + passed + "\n" + android.util.Log.getStackTraceString(e));
        } finally {
            if(AppState.running || AppState.starting) runOnMainSync(() -> AdVpnService.requestStop(c));
            try { RulesStore.save(c,false,beforeCustom); RulesStore.save(c,true,beforeAllow); } catch(IOException ignored) {}
        }
        finish(resultCode,result);
    }
    private void check(boolean condition,String name) { if(!condition)throw new AssertionError(name); passed.add(name); }
    private interface Condition { boolean get(); }
    private void waitUntil(Condition condition,long timeout,String label)throws InterruptedException {
        long end=SystemClock.elapsedRealtime()+timeout; while(!condition.get() && SystemClock.elapsedRealtime()<end)Thread.sleep(50);
        check(condition.get(),label+" ("+AppState.status+")");
    }
    private byte[] udp(byte[] query)throws IOException {
        try(DatagramSocket socket=new DatagramSocket()) {
            socket.connect(InetAddress.getByName("10.111.0.2"),53); socket.setSoTimeout(12000); socket.send(new DatagramPacket(query,query.length));
            byte[] data=new byte[8192]; DatagramPacket packet=new DatagramPacket(data,data.length); socket.receive(packet); return Arrays.copyOf(data,packet.getLength());
        }
    }
    private byte[] query(String name,int type)throws IOException {
        ByteArrayOutputStream b=new ByteArrayOutputStream(); DataOutputStream d=new DataOutputStream(b);
        d.writeShort(0x4312); d.writeShort(0x100); d.writeShort(1); d.writeShort(0); d.writeShort(0); d.writeShort(0);
        for(String label:name.split("\\.")) { byte[] bytes=label.getBytes(StandardCharsets.US_ASCII); d.writeByte(bytes.length); d.write(bytes); }
        d.writeByte(0); d.writeShort(type); d.writeShort(1); return b.toByteArray();
    }
}
