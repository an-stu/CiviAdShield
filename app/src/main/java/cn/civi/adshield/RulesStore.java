package cn.civi.adshield;

import android.content.Context;
import android.util.AtomicFile;
import cn.civi.adshield.core.DomainRules;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class RulesStore {
    public static final int MAX_BYTES = 8 * 1024 * 1024;
    private static volatile Snapshot current;
    private static DomainRules builtin;
    private RulesStore() {}
    public static final class Snapshot {
        public final DomainRules base, custom, allow;
        Snapshot(DomainRules b, DomainRules c, DomainRules a) { base=b; custom=c; allow=a; }
        public boolean blocks(String domain) { return !allow.matches(domain) && (base.matches(domain) || custom.matches(domain)); }
        public int count() { return base.size() + custom.size(); }
    }
    public static Snapshot get(Context c) throws IOException {
        Snapshot snapshot = current;
        if (snapshot != null) return snapshot;
        synchronized (RulesStore.class) {
            if (current == null) reload(c);
            return current;
        }
    }
    public static synchronized Snapshot reload(Context c) throws IOException {
        if (builtin == null) {
            try (Reader r = new InputStreamReader(c.getAssets().open("anti-ad-domains.txt"), StandardCharsets.UTF_8)) {
                builtin = DomainRules.load(r);
            }
        }
        DomainRules custom = DomainRules.load(new StringReader(read(c, false)));
        DomainRules allow = DomainRules.load(new StringReader(read(c, true)));
        current = new Snapshot(builtin, custom, allow);
        return current;
    }
    private static AtomicFile file(Context c, boolean allow) {
        return new AtomicFile(new File(c.getFilesDir(), allow ? "allow.txt" : "custom.txt"));
    }
    public static synchronized String read(Context c, boolean allow) throws IOException {
        AtomicFile f = file(c, allow);
        if (!f.getBaseFile().exists()) return "";
        try (InputStream in = f.openRead()) { return readLimited(in); }
    }
    public static String readLimited(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = new byte[8192]; int n;
        while ((n = in.read(b)) != -1) {
            if (out.size() + n > MAX_BYTES) throw new IOException("文件超过 8 MB，请缩小规则文件");
            out.write(b, 0, n);
        }
        return out.toString(StandardCharsets.UTF_8.name()).replace("\uFEFF", "");
    }
    public static synchronized int save(Context c, boolean allow, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_BYTES) throw new IOException("规则超过 8 MB");
        DomainRules parsed = DomainRules.load(new StringReader(text));
        if (!text.trim().isEmpty() && parsed.size() == 0) throw new IOException("未发现有效域名。支持纯域名、hosts、||域名^，不支持完整网页过滤规则。");
        AtomicFile f = file(c, allow);
        FileOutputStream out = null;
        try { out = f.startWrite(); out.write(bytes); f.finishWrite(out); }
        catch (IOException e) { if (out != null) f.failWrite(out); throw e; }
        reload(c);
        return parsed.size();
    }
    public static synchronized void allow(Context c, String domain) throws IOException {
        String normalized = DomainRules.normalize(domain);
        if (normalized == null) throw new IOException("域名格式不正确");
        save(c, true, read(c, true) + "\n" + normalized + "\n");
    }
    /** Domain-provider format. Drop blocked ancestors of whitelist entries to preserve whitelist intent. */
    public static void exportClash(Context c, OutputStream out) throws IOException {
        Snapshot s = get(c);
        Set<String> all = new TreeSet<>(s.base.domains()); all.addAll(s.custom.domains());
        Set<String> ancestorExceptions = new HashSet<>();
        for (String a : s.allow.domains()) {
            String d=a;
            while (true) { ancestorExceptions.add(d); int dot=d.indexOf('.'); if (dot<0) break; d=d.substring(dot+1); }
        }
        Writer w = new OutputStreamWriter(out, StandardCharsets.UTF_8);
        w.write("# 净屏 / anti-AD (MIT). domain rule-provider for Clash Meta / mihomo.\n");
        w.write("# Whitelist ancestors omitted to avoid blocking allowed subdomains.\npayload:\n");
        int count=0;
        for (String d : all) if (!s.allow.matches(d) && !ancestorExceptions.contains(d)) { w.write("  - '+." + d + "'\n"); count++; }
        if (count==0) w.write("  []\n");
        w.flush();
    }
}
