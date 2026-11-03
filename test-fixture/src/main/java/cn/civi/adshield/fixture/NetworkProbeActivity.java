package cn.civi.adshield.fixture;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Independent network probe for testing DNS behavior from a real, separate application process.
 * It deliberately does not call any production CiviAdShield DNS code.
 */
public final class NetworkProbeActivity extends Activity {
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_RESOLVER = "resolver";
    public static final String EXTRA_TOKEN = "token";

    private static final String PREFS_NAME = "fixture";
    private static final String DEFAULT_HOST = "ad.xiaomi.com";
    private static final String DEFAULT_RESOLVER = "10.111.0.2";
    private static final String DEFAULT_TOKEN = "network";
    private static final int DNS_PORT = 53;
    private static final int TIMEOUT_MS = 8_000;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final SecureRandom random = new SecureRandom();
    private volatile DatagramSocket activeUdpSocket;
    private volatile Socket activeTcpSocket;
    private volatile Thread workerThread;

    private TextView outputView;
    private String host;
    private String resolver;
    private String token;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        host = extraOrDefault(EXTRA_HOST, DEFAULT_HOST);
        resolver = extraOrDefault(EXTRA_RESOLVER, DEFAULT_RESOLVER);
        token = validToken(extraOrDefault(EXTRA_TOKEN, DEFAULT_TOKEN));

        ScrollView scrollView = new ScrollView(this);
        scrollView.setFillViewport(true);
        outputView = new TextView(this);
        outputView.setTextColor(0xff17362f);
        outputView.setTextSize(14);
        outputView.setPadding(dp(16), dp(16), dp(16), dp(16));
        outputView.setText("DNS probe running\nHost: " + host + "\nResolver: " + resolver);
        scrollView.addView(outputView, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(scrollView);

        workerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                runProbes();
            }
        }, "FixtureDnsProbe");
        workerThread.setDaemon(true);
        workerThread.start();
    }

    @Override
    protected void onDestroy() {
        Thread worker = workerThread;
        if (worker != null) {
            worker.interrupt();
        }
        closeQuietly(activeUdpSocket);
        closeQuietly(activeTcpSocket);
        super.onDestroy();
    }

    private void runProbes() {
        JSONObject report = new JSONObject();
        JSONObject probes = new JSONObject();
        put(report, "token", token);
        put(report, "host", host);
        put(report, "resolver", resolver);
        put(report, "probes", probes);
        persist(report);

        addProbe(report, probes, "udp_a", runDnsProbe(1, false));
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        addProbe(report, probes, "udp_aaaa", runDnsProbe(28, false));
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        addProbe(report, probes, "tcp_a", runDnsProbe(1, true));
        if (Thread.currentThread().isInterrupted()) {
            return;
        }
        addProbe(report, probes, "system_lookup", runSystemLookup());
        showReport(report.toString());
    }

    private JSONObject runDnsProbe(int recordType, boolean tcp) {
        long startedAt = SystemClock.elapsedRealtime();
        int queryId = random.nextInt(65_536);
        String transport = tcp ? "tcp" : "udp";
        JSONObject result = new JSONObject();
        put(result, "transport", transport);
        put(result, "recordType", recordType == 1 ? "A" : "AAAA");
        put(result, "id", queryId);
        put(result, "question", host);
        try {
            byte[] query = buildQuery(host, queryId, recordType);
            byte[] response = tcp ? tcpExchange(query) : udpExchange(query);
            DnsSummary summary = parseResponse(response, queryId, host, recordType);
            put(result, "valid", true);
            put(result, "matchedId", summary.id);
            put(result, "matchedQuestion", summary.question);
            put(result, "rcode", summary.rcode);
            put(result, "answerCount", summary.answerCount);
        } catch (Exception exception) {
            put(result, "valid", false);
            put(result, "exception", exceptionText(exception));
        } finally {
            put(result, "durationMillis", SystemClock.elapsedRealtime() - startedAt);
        }
        return result;
    }

    private JSONObject runSystemLookup() {
        long startedAt = SystemClock.elapsedRealtime();
        JSONObject result = new JSONObject();
        put(result, "host", "example.com");
        try {
            InetAddress[] addresses = InetAddress.getAllByName("example.com");
            org.json.JSONArray jsonAddresses = new org.json.JSONArray();
            for (InetAddress address : addresses) {
                jsonAddresses.put(address.getHostAddress());
            }
            put(result, "valid", addresses.length > 0);
            put(result, "addresses", jsonAddresses);
        } catch (Exception exception) {
            put(result, "valid", false);
            put(result, "exception", exceptionText(exception));
        } finally {
            put(result, "durationMillis", SystemClock.elapsedRealtime() - startedAt);
        }
        return result;
    }

    private byte[] udpExchange(byte[] query) throws IOException {
        InetAddress server = resolverAddress();
        DatagramSocket socket = new DatagramSocket();
        activeUdpSocket = socket;
        try {
            socket.connect(server, DNS_PORT);
            socket.setSoTimeout(TIMEOUT_MS);
            socket.send(new DatagramPacket(query, query.length));
            byte[] buffer = new byte[4096];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);
            byte[] bytes = new byte[response.getLength()];
            System.arraycopy(response.getData(), response.getOffset(), bytes, 0, bytes.length);
            return bytes;
        } finally {
            socket.close();
            activeUdpSocket = null;
        }
    }

    private byte[] tcpExchange(byte[] query) throws IOException {
        InetAddress server = resolverAddress();
        Socket socket = new Socket();
        activeTcpSocket = socket;
        long deadline = SystemClock.elapsedRealtime() + TIMEOUT_MS;
        try {
            socket.connect(new InetSocketAddress(server, DNS_PORT), TIMEOUT_MS);
            OutputStream output = socket.getOutputStream();
            output.write((query.length >>> 8) & 0xff);
            output.write(query.length & 0xff);
            output.write(query);
            output.flush();

            InputStream input = socket.getInputStream();
            byte[] lengthPrefix = new byte[2];
            readFully(socket, input, lengthPrefix, deadline);
            int responseLength = u16(lengthPrefix, 0);
            if (responseLength < 12) {
                throw new IOException("invalid TCP DNS response length");
            }
            byte[] response = new byte[responseLength];
            readFully(socket, input, response, deadline);
            return response;
        } finally {
            socket.close();
            activeTcpSocket = null;
        }
    }

    private void readFully(Socket socket, InputStream input, byte[] target, long deadline)
            throws IOException {
        int offset = 0;
        while (offset < target.length) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) {
                throw new SocketTimeoutException("DNS TCP probe exceeded 8 seconds");
            }
            socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, remaining));
            int count = input.read(target, offset, target.length - offset);
            if (count < 0) {
                throw new IOException("truncated TCP DNS response");
            }
            offset += count;
        }
    }

    private byte[] buildQuery(String domain, int id, int recordType) throws IOException {
        String normalized = normalizeHost(domain);
        String[] labels = normalized.split("\\.");
        int nameLength = 1;
        for (String label : labels) {
            nameLength += 1 + label.length();
        }
        byte[] query = new byte[12 + nameLength + 4];
        put16(query, 0, id);
        put16(query, 2, 0x0100); // Recursion desired.
        put16(query, 4, 1);
        int cursor = 12;
        for (String label : labels) {
            query[cursor++] = (byte) label.length();
            for (int index = 0; index < label.length(); index++) {
                query[cursor++] = (byte) label.charAt(index);
            }
        }
        query[cursor++] = 0;
        put16(query, cursor, recordType);
        put16(query, cursor + 2, 1);
        return query;
    }

    private DnsSummary parseResponse(byte[] response, int expectedId, String expectedHost,
                                     int expectedType) throws IOException {
        if (response == null || response.length < 12) {
            throw new IOException("DNS response header is truncated");
        }
        int id = u16(response, 0);
        int flags = u16(response, 2);
        if (id != expectedId || (flags & 0x8000) == 0 || u16(response, 4) != 1) {
            throw new IOException("DNS response ID or header did not match query");
        }

        ParsedName name = readName(response, 12);
        int cursor = name.end;
        if (cursor > response.length - 4) {
            throw new IOException("DNS response question is truncated");
        }
        int type = u16(response, cursor);
        int questionClass = u16(response, cursor + 2);
        String normalizedExpected = normalizeHost(expectedHost);
        if (!name.value.equalsIgnoreCase(normalizedExpected) || type != expectedType
                || questionClass != 1) {
            throw new IOException("DNS response question did not match query");
        }

        DnsSummary summary = new DnsSummary();
        summary.id = id;
        summary.question = name.value;
        summary.rcode = flags & 0x0f;
        summary.answerCount = u16(response, 6);
        return summary;
    }

    private ParsedName readName(byte[] packet, int start) throws IOException {
        StringBuilder name = new StringBuilder();
        int cursor = start;
        int end = -1;
        int expandedLength = 1;
        int hops = 0;
        boolean jumped = false;
        int labels = 0;
        while (true) {
            if (cursor < 0 || cursor >= packet.length) {
                throw new IOException("DNS name runs past response");
            }
            int length = packet[cursor] & 0xff;
            if ((length & 0xc0) == 0xc0) {
                if (cursor + 1 >= packet.length) {
                    throw new IOException("truncated DNS compression pointer");
                }
                int target = ((length & 0x3f) << 8) | (packet[cursor + 1] & 0xff);
                if (target >= cursor || target >= packet.length || ++hops > 128) {
                    throw new IOException("invalid DNS compression pointer");
                }
                if (!jumped) {
                    end = cursor + 2;
                    jumped = true;
                }
                cursor = target;
                continue;
            }
            if ((length & 0xc0) != 0) {
                throw new IOException("unsupported DNS label encoding");
            }
            cursor++;
            if (length == 0) {
                if (!jumped) {
                    end = cursor;
                }
                break;
            }
            if (length > 63 || cursor > packet.length - length) {
                throw new IOException("invalid DNS label length");
            }
            expandedLength += length + 1;
            if (expandedLength > 255) {
                throw new IOException("DNS name is too long");
            }
            if (labels++ > 0) {
                name.append('.');
            }
            for (int index = 0; index < length; index++) {
                int character = packet[cursor + index] & 0xff;
                if (character < 0x21 || character > 0x7e || character == '.') {
                    throw new IOException("DNS question is not printable ASCII");
                }
                name.append((char) character);
            }
            cursor += length;
        }
        if (labels == 0) {
            name.append('.');
        }
        return new ParsedName(name.toString(), end);
    }

    private InetAddress resolverAddress() throws IOException {
        String[] parts = resolver.split("\\.", -1);
        if (parts.length != 4) {
            throw new IOException("resolver must be an IPv4 address");
        }
        byte[] address = new byte[4];
        for (int index = 0; index < parts.length; index++) {
            if (parts[index].isEmpty() || parts[index].length() > 3) {
                throw new IOException("resolver must be an IPv4 address");
            }
            int octet;
            try {
                octet = Integer.parseInt(parts[index]);
            } catch (NumberFormatException invalid) {
                throw new IOException("resolver must be an IPv4 address", invalid);
            }
            if (octet < 0 || octet > 255) {
                throw new IOException("resolver must be an IPv4 address");
            }
            address[index] = (byte) octet;
        }
        return InetAddress.getByAddress(address);
    }

    private String normalizeHost(String value) throws IOException {
        if (value == null || value.isEmpty() || value.length() > 253) {
            throw new IOException("host must be a DNS name");
        }
        String normalized = value.endsWith(".")
                ? value.substring(0, value.length() - 1) : value;
        String[] labels = normalized.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.charAt(0) == '-'
                    || label.charAt(label.length() - 1) == '-') {
                throw new IOException("host must contain valid ASCII DNS labels");
            }
            for (int index = 0; index < label.length(); index++) {
                char character = label.charAt(index);
                boolean asciiLetter = (character >= 'A' && character <= 'Z')
                        || (character >= 'a' && character <= 'z');
                boolean digit = character >= '0' && character <= '9';
                if (!asciiLetter && !digit && character != '-') {
                    throw new IOException("host must contain valid ASCII DNS labels");
                }
            }
        }
        return normalized.toLowerCase(Locale.ROOT);
    }

    private void addProbe(JSONObject report, JSONObject probes, String name, JSONObject result) {
        try {
            probes.put(name, result);
            report.put("probes", probes);
        } catch (JSONException ignored) {
            // JSONObject accepts these keys and values; retain already recorded probes on failure.
        }
        persist(report);
    }

    private void persist(JSONObject report) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putString("network_" + token, report.toString())
                .apply();
    }

    private void showReport(final String value) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (!isFinishing() && outputView != null) {
                    outputView.setText(value);
                }
            }
        });
    }

    private String exceptionText(Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.isEmpty()) {
            return exception.getClass().getSimpleName();
        }
        return exception.getClass().getSimpleName() + ": " + message;
    }

    private String extraOrDefault(String key, String fallback) {
        String value = getIntent() == null ? null : getIntent().getStringExtra(key);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private String validToken(String value) {
        if (value.length() > 64) {
            return DEFAULT_TOKEN;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(character >= 'A' && character <= 'Z')
                    && !(character >= 'a' && character <= 'z')
                    && !(character >= '0' && character <= '9')
                    && character != '_' && character != '-' && character != '.') {
                return DEFAULT_TOKEN;
            }
        }
        return value;
    }

    private void put(JSONObject json, String key, Object value) {
        try {
            json.put(key, value);
        } catch (JSONException ignored) {
            // Only primitive values and JSON containers are added by this fixture.
        }
    }

    private void closeQuietly(DatagramSocket socket) {
        if (socket != null) {
            socket.close();
        }
    }

    private void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static int u16(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static void put16(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static final class DnsSummary {
        int id;
        String question;
        int rcode;
        int answerCount;
    }

    private static final class ParsedName {
        final String value;
        final int end;

        ParsedName(String value, int end) {
            this.value = value;
            this.end = end;
        }
    }
}
