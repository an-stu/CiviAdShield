package cn.civi.adshield;

import android.content.Context;
import android.util.AtomicFile;
import cn.civi.adshield.core.AdGuardDnsRules;
import cn.civi.adshield.core.DnsBlockPolicy;
import cn.civi.adshield.core.DomainRules;
import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public final class RulesStore {
    public static final int MAX_BYTES = 8 * 1024 * 1024;
    private static volatile Snapshot current;
    private static DomainRules builtin;
    private static AdGuardDnsRules adguard;
    private static JSONObject adguardMeta;
    private RulesStore() {}
    public static final class Snapshot {
        public final DomainRules base, custom, allow;
        public final AdGuardDnsRules adguard;
        public final boolean antiEnabled, adguardEnabled;
        public final String adguardDescription;
        public final DnsBlockPolicy policy;
        Snapshot(DomainRules b, DomainRules c, DomainRules a, AdGuardDnsRules g,
                 boolean anti, boolean enabled, String description) {
            base=b; custom=c; allow=a; adguard=g; antiEnabled=anti; adguardEnabled=enabled;
            adguardDescription=description;
            policy=new DnsBlockPolicy(b,c,a,g,anti,enabled);
        }
        public boolean blocks(String domain) { return policy.blocks(domain); }
        public int count() { return (antiEnabled?base.size():0) + (adguardEnabled?adguard.size():0) + custom.size(); }
    }
    public static Snapshot get(Context c) throws IOException {
        Snapshot s=current;
        if(s!=null)return s;
        synchronized(RulesStore.class) { if(current==null)reload(c); return current; }
    }
    public static synchronized Snapshot reload(Context c) throws IOException {
        if(builtin==null) try(Reader r=asset(c,"anti-ad-domains.txt")) { builtin=DomainRules.load(r); }
        if(adguard==null) loadAdGuard(c);
        DomainRules custom=DomainRules.load(new StringReader(read(c,false)));
        DomainRules allow=DomainRules.load(new StringReader(read(c,true)));
        String kind=adguardMeta.optString("source","official-bundled");
        String label=kind.equals("official-update")?"官方更新":kind.equals("local-import")?"本地导入":"官方内置";
        String date=adguardMeta.optString("upstreamLastModified",adguardMeta.optString("retrievedDate","未知日期"));
        if(date.matches("\\d{4}-\\d{2}-\\d{2}.*"))date=date.substring(0,10);
        current=new Snapshot(builtin,custom,allow,adguard,
            AppState.prefs(c).getBoolean("filter_anti_ad",true),
            AppState.prefs(c).getBoolean("filter_adguard_dns",true),label+" · "+date);
        return current;
    }
    private static Reader asset(Context c,String name)throws IOException {
        return new InputStreamReader(c.getAssets().open(name),StandardCharsets.UTF_8);
    }
    private static AtomicFile file(Context c,boolean allow) {
        return new AtomicFile(new File(c.getFilesDir(),allow?"allow.txt":"custom.txt"));
    }
    private static AtomicFile adguardFile(Context c,boolean meta) {
        return new AtomicFile(new File(c.getFilesDir(),meta?"adguard-dns-meta.json":"adguard-dns.txt"));
    }
    private static void loadAdGuard(Context c)throws IOException {
        AtomicFile data=adguardFile(c,false),meta=adguardFile(c,true);
        if(data.getBaseFile().exists() && meta.getBaseFile().exists()) {
            try(InputStream input=data.openRead();InputStream mi=meta.openRead()) {
                String text=readLimited(input);JSONObject m=new JSONObject(readLimited(mi));
                if(!sha256(text.getBytes(StandardCharsets.UTF_8)).equals(m.optString("sha256")))throw new IOException("订阅缓存校验失败");
                AdGuardDnsRules parsed=AdGuardDnsRules.load(new StringReader(text));
                if(parsed.acceptedRules()==0)throw new IOException("订阅缓存没有有效 DNS 规则");
                adguard=parsed;adguardMeta=m;return;
            } catch(Exception ignored) { /* The bundled source remains available offline. */ }
        }
        try(Reader r=asset(c,"filters/adguard-dns.txt");InputStream in=c.getAssets().open("filters/adguard-dns-meta.json")) {
            adguard=AdGuardDnsRules.load(r);adguardMeta=new JSONObject(readLimited(in));
        } catch(org.json.JSONException e) { throw new IOException("内置规则元信息无效",e); }
    }
    public static synchronized String read(Context c,boolean allow)throws IOException {
        AtomicFile f=file(c,allow);if(!f.getBaseFile().exists())return "";
        try(InputStream in=f.openRead()) { return readLimited(in); }
    }
    public static String readLimited(InputStream in)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;
        while((n=in.read(b))!=-1) { if(out.size()+n>MAX_BYTES)throw new IOException("文件超过 8 MB");out.write(b,0,n); }
        return out.toString(StandardCharsets.UTF_8.name()).replace("\uFEFF","");
    }
    private static void write(AtomicFile f,byte[] bytes)throws IOException {
        FileOutputStream out=null;
        try { out=f.startWrite();out.write(bytes);f.finishWrite(out); }
        catch(IOException e) { if(out!=null)f.failWrite(out);throw e; }
    }
    public static synchronized int save(Context c,boolean allow,String text)throws IOException {
        byte[] b=text.getBytes(StandardCharsets.UTF_8);if(b.length>MAX_BYTES)throw new IOException("规则超过 8 MB");
        DomainRules p=DomainRules.load(new StringReader(text));
        if(!text.trim().isEmpty() && p.size()==0)throw new IOException("未发现有效域名。网址、CSS/JS 规则无法在 DNS 层执行。");
        if(!allow && Arrays.stream(text.split("\n")).anyMatch(line -> {String v=line.trim();return !v.startsWith("!")&&!v.startsWith("#")&&(v.startsWith("@@")||v.contains("$"));}))
            throw new IOException("此文件含 AdGuard 例外或修饰符，请用“导入 AdGuard DNS 列表”，避免丢失规则语义。");
        write(file(c,allow),b);reload(c);return p.size();
    }
    public static synchronized void allow(Context c,String domain)throws IOException {
        String d=DomainRules.normalize(domain);if(d==null)throw new IOException("域名格式不正确");
        save(c,true,read(c,true)+"\n"+d+"\n");
    }
    public static AdGuardDnsRules installAdGuard(Context c,String text,String source)throws IOException {
        byte[] b=text.getBytes(StandardCharsets.UTF_8);if(b.length>MAX_BYTES)throw new IOException("规则超过 8 MB");
        AdGuardDnsRules parsed=AdGuardDnsRules.load(new StringReader(text));
        if(parsed.acceptedRules()==0)throw new IOException("没有可执行的 DNS 规则；网页 CSS、JS 和网址路径规则不能在此执行。");
        if(source.equals("official-update") && parsed.acceptedRules()<10000)throw new IOException("订阅有效规则过少，保留当前规则");
        JSONObject m=new JSONObject();
        try {
            m.put("source",source.equals("official-update")?source:"local-import");m.put("sha256",sha256(b));
            m.put("retrievedDate",new java.text.SimpleDateFormat("yyyy-MM-dd",Locale.ROOT).format(new Date()));
            for(String line:text.split("\n"))if(line.startsWith("! Last modified:")) {m.put("upstreamLastModified",line.substring(16).trim());break;}
        } catch(org.json.JSONException e) {throw new IOException(e);}
        synchronized(RulesStore.class) {
            write(adguardFile(c,false),b);write(adguardFile(c,true),m.toString().getBytes(StandardCharsets.UTF_8));
            adguard=parsed;adguardMeta=m;reload(c);
        }
        return parsed;
    }
    public static synchronized void resetAdGuard(Context c)throws IOException {
        adguardFile(c,false).delete();adguardFile(c,true).delete();adguard=null;adguardMeta=null;reload(c);
    }
    private static String sha256(byte[] data)throws IOException {
        try { byte[] digest=MessageDigest.getInstance("SHA-256").digest(data);StringBuilder s=new StringBuilder();for(byte b:digest)s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString(); }
        catch(java.security.NoSuchAlgorithmException e) {throw new IOException(e);}
    }
    /** Domain providers cannot encode every exception. Drop conflicting ancestors conservatively. */
    public static void exportClash(Context c,OutputStream out)throws IOException {
        Snapshot s=get(c);Set<String> all=new TreeSet<>(s.custom.domains());
        if(s.antiEnabled)all.addAll(s.base.domains());if(s.adguardEnabled)all.addAll(s.adguard.blockDomains());
        Set<String> exceptions=new HashSet<>(s.allow.domains());
        if(s.adguardEnabled)for(String d:s.adguard.exceptionDomains())if(!s.custom.matches(d)&&s.adguard.decide(d)==AdGuardDnsRules.Decision.ALLOW)exceptions.add(d);
        Set<String> ancestors=new HashSet<>();for(String e:exceptions) {String d=e;while(true){ancestors.add(d);int dot=d.indexOf('.');if(dot<0)break;d=d.substring(dot+1);}}
        Writer w=new OutputStreamWriter(out,StandardCharsets.UTF_8);w.write("# 净屏 / anti-AD (MIT) + AdGuard DNS (GPL-3.0)\n# Conflicting exception ancestors omitted.\npayload:\n");
        int n=0;for(String d:all)if(s.blocks(d)&&!ancestors.contains(d)){w.write("  - '+."+d+"'\n");n++;}
        if(n==0)w.write("  []\n");w.flush();
    }
}
