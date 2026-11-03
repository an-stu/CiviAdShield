package cn.civi.adshield;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.*;
import android.os.*;
import android.provider.Settings;
import android.text.*;
import android.view.*;
import android.widget.*;
import cn.civi.adshield.core.DomainRules;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public final class MainActivity extends Activity {
    private static final int GREEN = 0xff137c65, INK = 0xff19372f, MUTED = 0xff61756e, BG = 0xfff4f7f4;
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView status, counters, ruleCount, scopeStatus;
    private Button vpnButton;
    private LinearLayout content;
    private final Runnable refresh = new Runnable() { public void run() { updateStatus(); handler.postDelayed(this, 1000); } };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        removeLegacySkipPreferences();
        ScrollView scroll = new ScrollView(this); scroll.setBackgroundColor(BG); scroll.setFillViewport(true);
        content = new LinearLayout(this); content.setOrientation(LinearLayout.VERTICAL); content.setPadding(dp(22), dp(16), dp(22), dp(30));
        scroll.addView(content);
        scroll.setClipToPadding(true);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            scroll.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            content.setPadding(dp(22), dp(16), dp(22), dp(30));
            return insets;
        });
        setContentView(scroll);
        label(content, "XIAOMI AD SHIELD", 12, GREEN, true);
        TextView title = label(content, "净屏", 44, INK, true); title.setPadding(0,dp(12),0,0);
        label(content, "少一点打扰，多一点专注。", 16, MUTED, false);
        LinearLayout protection = card();
        label(protection, "广告域名拦截", 21, INK, true);
        status = label(protection, "尚未启动", 15, MUTED, false);
        counters = label(protection, "", 19, GREEN, true);
        scopeStatus = label(protection, "", 13, MUTED, false);
        vpnButton = button(protection, "开启域名拦截", this::startOrStop);
        label(protection, "本地 DNS 过滤 · 免 Root · Wi-Fi / 移动网络", 12, MUTED, false);
        LinearLayout scope = card();
        label(scope, getString(R.string.network_scope_title), 21, INK, true);
        label(scope, getString(R.string.network_scope_description), 14, MUTED, false);
        LinearLayout rules = card();
        label(rules, "拦截规则", 21, INK, true);
        ruleCount = label(rules, "正在加载内置规则…", 14, MUTED, false);
        button(rules, "最近拦截 · 一键加入白名单", this::showBlocked);
        button(rules, "编辑白名单", () -> editRules(true));
        button(rules, "添加自定义域名", () -> editRules(false));
        button(rules, "导入域名 / hosts 规则", this::importRules);
        button(rules, "仅拦截指定应用（可选）", () -> chooseApps(true));
        button(rules, "排除应用（不拦截其 DNS）", () -> chooseApps(false));
        LinearLayout clash = card();
        label(clash, "使用 Clash Meta 时", 21, INK, true);
        label(clash, "Android 同时只能运行一个 VPN。使用 Clash 时，请暂停净屏；导出规则后，可由 Clash 执行域名拦截。", 14, MUTED, false);
        button(clash, "暂停拦截，查看 Clash 接入说明", () -> { stopVpn(); showClash(); });
        button(clash, "导出 Clash 广告规则", this::exportClash);
        LinearLayout help = card();
        label(help, "设置与说明", 21, INK, true);
        button(help, "DNS 上游与网络设置", this::dnsSettings);
        button(help, "MIUI / HyperOS 后台设置", this::showSetup);
        button(help, "打开应用信息", this::openAppInfo);
        button(help, "后台与省电设置", () -> openSettings(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
        button(help, "设备与 Android 版本", this::showCompatibility);
        button(help, "隐私、效果边界与规则来源", this::showPrivacy);
        button(help, "清空本机统计与近期记录", () -> new AlertDialog.Builder(this).setMessage("清空拦截次数和近期拦截域名？规则与白名单会保留。")
            .setPositiveButton("清空", (d,w) -> { AppState.clear(this); updateStatus(); }).setNegativeButton("取消",null).show());
        label(content, "小米 / Redmi / POCO · Android 8.0+ · v" + getString(R.string.app_version), 12, MUTED, false);
        label(content, "设备与系统版本可能影响后台行为；请查看设备信息并自行验证。", 12, MUTED, false);
        background(() -> RulesStore.get(this), s -> { updateStatus(); showRuleCount(s); });
    }
    @Override protected void onResume() { super.onResume(); handler.removeCallbacks(refresh); refresh.run(); }
    @Override protected void onPause() { handler.removeCallbacks(refresh); super.onPause(); }
    @Override protected void onDestroy() { handler.removeCallbacksAndMessages(null); io.shutdown(); super.onDestroy(); }
    private void removeLegacySkipPreferences() {
        android.content.SharedPreferences prefs = AppState.prefs(this);
        if (prefs.contains("skip_enabled") || prefs.contains("skip_packages") || prefs.contains("skip_count")) {
            prefs.edit().remove("skip_enabled").remove("skip_packages").remove("skip_count").apply();
        }
    }
    private void updateStatus() {
        if (status == null) return;
        status.setText(AppState.status);
        vpnButton.setText(AppState.running || AppState.starting ? "暂停域名拦截" : "开启域名拦截");
        counters.setText(getString(R.string.counter_stats, AppState.prefs(this).getLong("blocked_count", 0)));
        int only=AppState.prefs(this).getStringSet("dns_only_packages",Collections.emptySet()).size();
        int excluded=AppState.prefs(this).getStringSet("dns_bypass_packages",Collections.emptySet()).size();
        scopeStatus.setText(only>0?getString(R.string.scope_only,only):excluded>0?getString(R.string.scope_excluded,excluded):getString(R.string.scope_all));
    }
    private void startOrStop() {
        if (AppState.running || AppState.starting) { stopVpn(); return; }
        new AlertDialog.Builder(this).setTitle("开启本地 DNS 拦截")
            .setMessage("净屏会建立本地 VPN，仅处理系统交给它的 DNS 请求，并在本机匹配广告域名。正常域名默认发送给阿里 DNS（223.5.5.5），失败时发送给腾讯 DNS（119.29.29.29），未加密；可在“DNS 上游”更改。\n\n会替换当前的 Clash 等 VPN。若开启了系统“私人 DNS”或应用自带安全 DNS，可能绕过过滤。请先关闭其他 VPN，并把私人 DNS 调整为关闭后测试。")
            .setPositiveButton("继续并授权 VPN", (d,w) -> {
                if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                    requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 101);
                Intent prepare = android.net.VpnService.prepare(this);
                if (prepare == null) launchVpn(); else startActivityForResult(prepare,100);
            }).setNegativeButton("取消",null).show();
    }
    private void launchVpn() {
        AppState.starting=true; AppState.status="等待启动…"; updateStatus();
        try { startForegroundService(new Intent(this, AdVpnService.class)); }
        catch (RuntimeException e) { AppState.starting=false; AppState.status="无法启动，请重新打开应用后再试"; updateStatus(); }
    }
    private void stopVpn() {
        AdVpnService.requestStop(this);
        AppState.status="已暂停，可使用 Clash Meta"; AppState.starting=false; updateStatus();
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request,result,data);
        if (request==100) { if(result==RESULT_OK) launchVpn(); else { AppState.status="未授权 VPN"; updateStatus(); } return; }
        if (result!=RESULT_OK || data==null || data.getData()==null) return;
        Uri uri=data.getData();
        if (request==500) background(() -> {
            try (InputStream in=getContentResolver().openInputStream(uri)) {
                if (in==null) throw new IOException("无法读取文件");
                String text=RulesStore.readLimited(in); DomainRules parsed=DomainRules.load(new StringReader(text));
                if(parsed.size()==0) throw new IOException("文件中没有有效域名");
                return new ImportData(text,parsed.size());
            }
        }, value -> new AlertDialog.Builder(this).setTitle("导入 " + value.count + " 条域名规则")
            .setMessage("将替换当前自定义拦截规则；内置规则和白名单会保留。格式不支持的行会忽略。")
            .setPositiveButton("替换并导入", (d,w) -> background(() -> RulesStore.save(this,false,value.text), count -> { toast("已导入 " + count + " 条规则"); updateRuleCount(); }))
            .setNegativeButton("取消",null).show());
        if(request==600) background(() -> { try(OutputStream out=getContentResolver().openOutputStream(uri,"wt")) { if(out==null) throw new IOException("无法写入文件"); RulesStore.exportClash(this,out); } return true; }, ok -> message("已导出", "请将规则文件交给 Clash Meta，并按接入说明添加 rule-provider 与 RULE-SET。此文件是域名规则集，不能直接作为完整订阅导入。"));
    }
    private record ImportData(String text,int count) {}
    private void importRules() {
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent,500);
    }
    private void exportClash() {
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/yaml").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"civi-ads.yaml");
        startActivityForResult(intent,600);
    }
    private void updateRuleCount() { background(() -> RulesStore.get(this), this::showRuleCount); }
    private void showRuleCount(RulesStore.Snapshot s) { ruleCount.setText(getString(R.string.rules_summary, s.base.size(), s.custom.size(), s.allow.size())); }
    private void editRules(boolean allow) {
        background(() -> RulesStore.read(this,allow), text -> {
            if(text.length()>200000) { message("规则文件较大", "请使用文件导入替换自定义规则，避免编辑大量文本导致卡顿。"); return; }
            EditText edit=new EditText(this); edit.setText(text); edit.setTextSize(14); edit.setGravity(Gravity.TOP); edit.setMinLines(5); edit.setMaxLines(12); edit.setHint("每行一个域名，例如 ads.example.com\n域名及其子域名都会匹配");
            edit.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            edit.setFilters(new InputFilter[]{new InputFilter.LengthFilter(200000)});
            AlertDialog dialog=new AlertDialog.Builder(this).setTitle(allow?"白名单 · 优先放行":"自定义拦截域名")
                .setMessage("支持纯域名、hosts 和 ||域名^。不支持网页元素规则。留空保存可清除这部分规则。")
                .setView(edit).setPositiveButton("保存",null).setNegativeButton("取消",null).create();
            dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> background(() -> RulesStore.save(this,allow,edit.getText().toString()), count -> { toast("已保存 " + count + " 条"); dialog.dismiss(); updateRuleCount(); })));
            dialog.show();
        });
    }
    private void showBlocked() {
        List<String> domains=AppState.recent();
        if(domains.isEmpty()) { message("近期拦截", "暂无记录。开启拦截后，最多显示本次进程中的 60 个被拦截域名。点击域名可加入白名单。这里不记录普通访问域名。"); return; }
        new AlertDialog.Builder(this).setTitle("近期拦截 · 点击放行")
            .setItems(domains.toArray(new String[0]), (d,which) -> new AlertDialog.Builder(this).setTitle("加入白名单？").setMessage(domains.get(which)+"\n此域名及其子域名将放行。修改后可能需要重新打开受影响的应用，等待其 DNS 缓存失效。")
                .setPositiveButton("放行",(a,b) -> background(() -> { RulesStore.allow(this,domains.get(which)); return true; },ok -> { toast("已加入白名单"); updateRuleCount(); }))
                .setNegativeButton("取消",null).show()).setNegativeButton("关闭",null).show();
    }
    private record AppItem(String pkg,String label) { @Override public String toString(){ return label+"\n"+pkg; } }
    private void chooseApps(boolean only) {
        background(() -> {
            Intent launcher=new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
            Map<String,AppItem> found=new TreeMap<>();
            for(ResolveInfo r:getPackageManager().queryIntentActivities(launcher,0)) {
                String pkg=r.activityInfo.packageName;
                if(!pkg.equals(getPackageName())) found.put(pkg,new AppItem(pkg,r.loadLabel(getPackageManager()).toString()));
            }
            List<AppItem> apps=new ArrayList<>(found.values()); apps.sort(Comparator.comparing(a -> a.label)); return apps;
        }, apps -> {
            String key=only?"dns_only_packages":"dns_bypass_packages";
            Set<String> chosen=new HashSet<>(AppState.prefs(this).getStringSet(key,Collections.emptySet()));
            Set<String> installedChoices=new HashSet<>();
            for(AppItem app:apps) installedChoices.add(app.pkg);
            chosen.retainAll(installedChoices);
            LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL); box.setPadding(dp(18),0,dp(18),0);
            EditText search=new EditText(this); search.setSingleLine(); search.setHint("搜索应用名称或包名");
            search.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            search.setImeOptions(android.view.inputmethod.EditorInfo.IME_ACTION_DONE);
            search.setOnEditorActionListener((v,action,event) -> {
                if(action==android.view.inputmethod.EditorInfo.IME_ACTION_DONE) { hideKeyboard(search); return true; }
                return false;
            });
            box.addView(search,row());
            ListView list=new ListView(this); list.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE); box.addView(list,new LinearLayout.LayoutParams(-1,dp(260)));
            List<AppItem> visible=new ArrayList<>(apps);
            ArrayAdapter<AppItem> adapter=new ArrayAdapter<>(this,android.R.layout.simple_list_item_multiple_choice,visible); list.setAdapter(adapter);
            Runnable checks=() -> { list.clearChoices(); for(int i=0;i<visible.size();i++) list.setItemChecked(i,chosen.contains(visible.get(i).pkg)); };
            checks.run();
            list.setOnItemClickListener((p,v,pos,id) -> { String pkg=visible.get(pos).pkg; if(list.isItemChecked(pos)) chosen.add(pkg); else chosen.remove(pkg); hideKeyboard(search); });
            search.addTextChangedListener(new TextWatcher() {
                public void beforeTextChanged(CharSequence s,int start,int count,int after){} public void onTextChanged(CharSequence s,int start,int before,int count) {
                    String q=s.toString().toLowerCase(Locale.ROOT); visible.clear(); for(AppItem a:apps) if(a.toString().toLowerCase(Locale.ROOT).contains(q)) visible.add(a); adapter.notifyDataSetChanged(); checks.run();
                } public void afterTextChanged(Editable e){}
            });
            AlertDialog chooser=new AlertDialog.Builder(this).setTitle(only?"仅拦截选中的应用":"排除应用的 DNS 拦截")
                .setMessage(only?"选中后只拦截这些应用的 DNS。留空表示保护全部应用。保存会清空排除列表；暂停并重新开启后生效。":"选中的应用不会经过净屏 DNS 过滤。保存会清空仅指定列表，恢复全局保护；暂停并重新开启后生效。")
                .setView(box).setPositiveButton("保存",(d,w)-> { AppState.prefs(this).edit().putStringSet(key,chosen).remove(only?"dns_bypass_packages":"dns_only_packages").apply(); updateStatus(); toast("已保存，重新开启域名拦截后生效"); })
                .setNegativeButton("取消",null).create();
            chooser.setOnShowListener(d -> chooser.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE));
            chooser.show();
        });
    }
    private void dnsSettings() {
        EditText edit=new EditText(this); edit.setSingleLine(); edit.setText(AppState.prefs(this).getString("upstream","223.5.5.5")); edit.setInputType(android.text.InputType.TYPE_CLASS_PHONE);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("DNS 上游（IPv4 地址）")
            .setMessage("普通域名会明文发送给此解析器。默认 223.5.5.5，超时回退 119.29.29.29；自定义地址不回退。修改立即用于新请求。若完全断网，先暂停拦截。\n\n系统私人 DNS 或应用自带 DoH 可绕过拦截。")
            .setView(edit).setPositiveButton("保存",null).setNeutralButton("系统网络设置",(d,w)->openSettings(Settings.ACTION_WIRELESS_SETTINGS)).setNegativeButton("取消",null).create();
        dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String ip=edit.getText().toString().trim();
            if(!validIpv4(ip) || ip.startsWith("127.") || ip.startsWith("0.") || ip.equals("10.111.0.2") || Integer.parseInt(ip.split("\\.")[0])>=224) { edit.setError("请输入可用的 DNS IPv4 地址"); return; }
            AppState.prefs(this).edit().putString("upstream",ip).apply(); dialog.dismiss(); toast("DNS 上游已保存");
        })); dialog.show();
    }
    private static boolean validIpv4(String ip) {
        String[] parts=ip.split("\\.",-1); if(parts.length!=4)return false;
        for(String p:parts) { if(!p.matches("[0-9]{1,3}"))return false; if(Integer.parseInt(p)>255)return false; } return true;
    }
    private void showClash() {
        message("Clash Meta / mihomo 接入", "1. 净屏域名拦截保持暂停，开启 Clash。\n2. 导出 civi-ads.yaml，放入 Clash 可读取的 ruleset 目录。\n3. 在现有配置的 rule-providers 中添加：\n\ncivi-ads:\n  type: file\n  behavior: domain\n  format: yaml\n  path: ./ruleset/civi-ads.yaml\n\n4. 在 rules 的宽泛放行规则与 MATCH 之前添加：\n- RULE-SET,civi-ads,REJECT\n\n不要覆盖现有订阅、代理节点或分组。不同客户端的本地文件导入方式不同；详见项目中的 CLASH.md。规则导出会保留白名单意图，可能同时放行其上级域名。更新白名单后需重新导出。");
    }
    private void showSetup() { message("MIUI / HyperOS 后台设置", "开启域名拦截时按系统提示授权 VPN。若后台运行不稳定：\n\n1. 打开应用信息，在自启动、后台运行、通知和电池等页面按需允许净屏在后台运行。\n2. 在系统省电设置中将净屏设为“不受限”或“无限制”（若系统提供）。\n3. 可在最近任务中锁定净屏（若系统提供）。\n\n不同 MIUI / HyperOS 版本的菜单名称和位置可能不同。本应用不会自动开机启动，也不启用始终开启 VPN；重启后请手动开启域名拦截。"); }
    private void showCompatibility() {
        String manufacturer=Build.MANUFACTURER==null?"未知":Build.MANUFACTURER;
        String brand=Build.BRAND==null?"未知":Build.BRAND;
        String model=Build.MODEL==null?"未知":Build.MODEL;
        String release=Build.VERSION.RELEASE==null?"未知":Build.VERSION.RELEASE;
        message("设备与 Android 版本", "制造商："+manufacturer+"\n品牌："+brand+"\n型号："+model+"\nAndroid："+release+" (API "+Build.VERSION.SDK_INT+")\n\n本应用面向 Android 8.0+ 的小米、Redmi、POCO 设备。系统 API 兼容范围不代表已验证所有机型；后台、省电与 VPN 行为仍需按你的设备和系统版本实测。");
    }
    private void showPrivacy() { message("隐私与效果边界", "净屏不接入统计、广告或账户服务，不安装 CA 证书，也不解密 HTTPS。不请求无障碍服务权限，也不会代你操作其他应用。\n\nVPN 仅处理系统交给本地解析器的 DNS 请求，不转发普通网页或视频流量。普通域名会发送给所选 DNS 上游；上游及网络运营方可能观察这些明文查询。\n\n仅在本机保存拦截次数、规则、白名单和 DNS 排除应用列表。最多 60 个被拦截域名仅保存在进程内存中。应用关闭备份。\n\n域名过滤可拦截已知广告域名或落地页域名的 DNS 请求；与正常 API 共用域名的内容、缓存广告、应用内嵌广告、自带加密 DNS 或硬编码 IP 可能绕过过滤。它不能全局阻止其他应用显式拉起应用，也不保证拦截所有广告。误拦截可添加白名单或排除应用。\n\n内置 anti-AD 规则，MIT 许可：\nhttps://github.com/privacy-protection-tools/anti-AD\n版本 20261102061401；不自动联网更新，可自行导入新规则。Android 8.0+。"); }
    private void openAppInfo() {
        Intent intent=new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:"+getPackageName()));
        try { startActivity(intent); } catch(ActivityNotFoundException e) { toast("系统未提供此设置入口，请手动打开应用信息"); }
    }
    private void openSettings(String action) { try { startActivity(new Intent(action)); } catch(ActivityNotFoundException e) { toast("系统未提供此设置入口，请手动进入设置"); } }
    private void hideKeyboard(View source) {
        getSystemService(android.view.inputmethod.InputMethodManager.class).hideSoftInputFromWindow(source.getWindowToken(),0);
        source.clearFocus();
    }
    private void message(String title,String body) { new AlertDialog.Builder(this).setTitle(title).setMessage(body).setPositiveButton("知道了",null).show(); }
    private void toast(String s) { Toast.makeText(this,s,Toast.LENGTH_LONG).show(); }
    private interface Result<T> { void accept(T value); }
    private <T> void background(Callable<T> work,Result<T> done) {
        if(io.isShutdown())return;
        io.execute(() -> {
            try { T value=work.call(); handler.post(() -> { if(!isFinishing() && !isDestroyed()) done.accept(value); }); }
            catch(Exception e) { handler.post(() -> { if(!isFinishing() && !isDestroyed()) message("操作未完成",e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()); }); }
        });
    }
    private int dp(float n) { return Math.round(n*getResources().getDisplayMetrics().density); }
    private LinearLayout.LayoutParams row() { LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2); p.topMargin=dp(8); return p; }
    private LinearLayout card() {
        LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL); box.setPadding(dp(20),dp(20),dp(20),dp(18));
        GradientDrawable bg=new GradientDrawable(); bg.setColor(Color.WHITE); bg.setCornerRadius(dp(20)); box.setBackground(bg);
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2); p.topMargin=dp(20); p.bottomMargin=dp(2); content.addView(box,p); return box;
    }
    private TextView label(LinearLayout parent,String text,float size,int color,boolean bold) {
        TextView v=new TextView(this); v.setText(text); v.setTextSize(size); v.setTextColor(color); v.setLineSpacing(dp(3),1); if(bold)v.setTypeface(Typeface.DEFAULT,Typeface.BOLD); parent.addView(v,row()); return v;
    }
    private Button button(LinearLayout parent,String text,Runnable action) {
        Button b=new Button(this); b.setText(text); b.setTextSize(14); b.setAllCaps(false); b.setTextColor(GREEN); b.setMinHeight(dp(48));
        b.setOnClickListener(v->action.run()); parent.addView(b,row()); return b;
    }
}
