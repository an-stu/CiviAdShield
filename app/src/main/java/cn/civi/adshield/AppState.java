package cn.civi.adshield;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** Only blocked-domain events are kept in memory; no browsing history is stored. */
public final class AppState {
    private AppState() {}
    public static volatile boolean running;
    public static volatile boolean starting;
    public static volatile String status = "尚未启动";
    private static final ArrayDeque<String> recent = new ArrayDeque<>();
    public static SharedPreferences prefs(Context c) { return c.getSharedPreferences("adshield", Context.MODE_PRIVATE); }
    public static synchronized void blocked(Context c, String domain) {
        SharedPreferences p = prefs(c);
        p.edit().putLong("blocked_count", p.getLong("blocked_count", 0) + 1).apply();
        recent.remove(domain);
        recent.addFirst(domain);
        while (recent.size() > 60) recent.removeLast();
    }
    public static synchronized List<String> recent() { return new ArrayList<>(recent); }
    public static synchronized void clear(Context c) {
        recent.clear();
        prefs(c).edit().putLong("blocked_count", 0).apply();
    }
}
