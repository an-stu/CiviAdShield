package cn.civi.adshield;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.SharedPreferences;
import android.graphics.Rect;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import cn.civi.adshield.core.SkipPolicy;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;

/**
 * Opt-in, package-scoped splash-ad skip helper. It never performs gestures or backs out of a
 * screen; it only clicks a visible, enabled, clickable node with a conservative skip-ad label.
 */
public final class SkipAccessibilityService extends AccessibilityService {
    private static final String PREFS_NAME = "adshield";
    private static final String KEY_SKIP_ENABLED = "skip_enabled";
    private static final String KEY_SKIP_PACKAGES = "skip_packages";
    private static final String KEY_SKIP_COUNT = "skip_count";

    private static final long LAUNCH_WINDOW_MS = 8_000L;
    private static final long MIN_SCAN_INTERVAL_MS = 200L;
    private static final int MAX_NODES_PER_SCAN = 180;
    private static final int MAX_TREE_DEPTH = 15;

    private String foregroundPackage;
    private boolean launchWindowActive;
    private long launchWindowStartedAt;
    private boolean clickedInLaunchWindow;
    private boolean hasScanned;
    private long lastScanAt;

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        AccessibilityServiceInfo info = getServiceInfo();
        if (info != null) {
            info.eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
                    | AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED;
            info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
            info.notificationTimeout = 100;
            info.flags |= AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
            setServiceInfo(info);
        }
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) {
            return;
        }

        int eventType = event.getEventType();
        if (eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
                && eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {
            return;
        }

        String eventPackage = event.getPackageName() == null
                ? null : event.getPackageName().toString();
        long now = SystemClock.uptimeMillis();

        if (eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            boolean packageTransition = !samePackage(foregroundPackage, eventPackage);
            foregroundPackage = eventPackage;
            if (packageTransition) {
                endLaunchWindow();
                if (isExplicitlyAllowed(eventPackage)) {
                    launchWindowActive = true;
                    launchWindowStartedAt = now;
                }
            } else if (launchWindowActive && !isExplicitlyAllowed(eventPackage)) {
                // A preference change can close an active window immediately; re-enabling while
                // this package remains foreground does not start a new window.
                endLaunchWindow();
            }
        }

        if (!isWindowCurrent(now) || !samePackage(foregroundPackage, eventPackage)
                || clickedInLaunchWindow) {
            return;
        }
        if (hasScanned && now - lastScanAt < MIN_SCAN_INTERVAL_MS) {
            return;
        }
        hasScanned = true;
        lastScanAt = now;
        scanAndClick(eventPackage, now);
    }

    @Override
    public void onInterrupt() {
        clearTracking();
    }

    @Override
    public void onDestroy() {
        // This service schedules no delayed work, so clearing tracking cancels all pending state.
        clearTracking();
        super.onDestroy();
    }

    private void scanAndClick(String expectedPackage, long scanStartedAt) {
        if (!isWindowCurrent(scanStartedAt)
                || !samePackage(foregroundPackage, expectedPackage)
                || !isExplicitlyAllowed(expectedPackage)) {
            return;
        }

        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) {
            return;
        }
        try {
            CharSequence rootPackage = root.getPackageName();
            if (rootPackage == null || !expectedPackage.contentEquals(rootPackage)) {
                return;
            }
            inspectTree(root, expectedPackage);
        } finally {
            root.recycle();
        }
    }

    private void inspectTree(AccessibilityNodeInfo root, String expectedPackage) {
        ArrayDeque<NodeAtDepth> queue = new ArrayDeque<>();
        queue.addLast(new NodeAtDepth(root, 0, false));
        int discovered = 1;
        int visited = 0;
        int screenWidth = getResources().getDisplayMetrics().widthPixels;
        int screenHeight = getResources().getDisplayMetrics().heightPixels;

        try {
            while (!queue.isEmpty() && visited < MAX_NODES_PER_SCAN) {
                NodeAtDepth current = queue.removeFirst();
                AccessibilityNodeInfo node = current.node;
                visited++;
                try {
                    if (isWindowCurrent(SystemClock.uptimeMillis())
                            && samePackage(foregroundPackage, expectedPackage)
                            && nodeIsFromPackage(node, expectedPackage)
                            && isVisibleEnabledClickable(node)
                            && isInAllowedBounds(node, screenWidth, screenHeight)
                            && hasSkipAdLabel(node)
                            && isExplicitlyAllowed(expectedPackage)
                            && isWindowCurrent(SystemClock.uptimeMillis())) {
                        if (node.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                            clickedInLaunchWindow = true;
                            incrementSkipCount();
                            break;
                        }
                    }

                    if (current.depth >= MAX_TREE_DEPTH || discovered >= MAX_NODES_PER_SCAN) {
                        continue;
                    }
                    int childCount = node.getChildCount();
                    for (int index = 0; index < childCount && discovered < MAX_NODES_PER_SCAN;
                         index++) {
                        AccessibilityNodeInfo child = node.getChild(index);
                        if (child != null) {
                            queue.addLast(new NodeAtDepth(child, current.depth + 1, true));
                            discovered++;
                        }
                    }
                } finally {
                    if (current.owned) {
                        node.recycle();
                    }
                }
            }
        } finally {
            while (!queue.isEmpty()) {
                NodeAtDepth remaining = queue.removeFirst();
                if (remaining.owned) {
                    remaining.node.recycle();
                }
            }
        }
    }

    private boolean isWindowCurrent(long now) {
        if (!launchWindowActive) {
            return false;
        }
        if (now - launchWindowStartedAt >= LAUNCH_WINDOW_MS) {
            endLaunchWindow();
            return false;
        }
        if (!isExplicitlyAllowed(foregroundPackage)) {
            endLaunchWindow();
            return false;
        }
        return true;
    }

    private boolean isExplicitlyAllowed(String packageName) {
        if (packageName == null || packageName.isEmpty() || isExcludedPackage(packageName)) {
            return false;
        }
        SharedPreferences preferences = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        if (!preferences.getBoolean(KEY_SKIP_ENABLED, false)) {
            return false;
        }
        Set<String> packages = preferences.getStringSet(KEY_SKIP_PACKAGES,
                Collections.<String>emptySet());
        return packages != null && packages.contains(packageName);
    }

    private boolean isExcludedPackage(String packageName) {
        if (getPackageName().equals(packageName)) {
            return true;
        }
        String normalized = packageName.toLowerCase(Locale.ROOT);
        if ("com.android.settings".equals(normalized)
                || "com.android.systemui".equals(normalized)
                || "com.miui.securitycenter".equals(normalized)
                || "com.lbe.security.miui".equals(normalized)
                || normalized.contains("packageinstaller")
                || normalized.contains("permissioncontroller")
                || normalized.contains("launcher")) {
            return true;
        }
        // Common launchers that do not include the word "launcher" in their package ID.
        return "com.miui.home".equals(normalized)
                || "com.huawei.android.launcher".equals(normalized)
                || "com.coloros.launcher".equals(normalized)
                || "com.oppo.launcher".equals(normalized)
                || "com.vivo.launcher".equals(normalized)
                || "com.oneplus.launcher".equals(normalized)
                || "org.lineageos.trebuchet".equals(normalized)
                || "com.sec.android.app.launcher".equals(normalized);
    }

    private boolean nodeIsFromPackage(AccessibilityNodeInfo node, String expectedPackage) {
        CharSequence nodePackage = node.getPackageName();
        return nodePackage != null && expectedPackage.contentEquals(nodePackage);
    }

    private boolean isVisibleEnabledClickable(AccessibilityNodeInfo node) {
        return node.isVisibleToUser() && node.isEnabled() && node.isClickable();
    }

    private boolean isInAllowedBounds(AccessibilityNodeInfo node, int screenWidth,
                                      int screenHeight) {
        Rect bounds = new Rect();
        node.getBoundsInScreen(bounds);
        return SkipPolicy.allowedBounds(bounds.left, bounds.top, bounds.right, bounds.bottom,
                screenWidth, screenHeight);
    }

    private boolean hasSkipAdLabel(AccessibilityNodeInfo node) {
        return SkipPolicy.matchesLabel(asString(node.getText()))
                || SkipPolicy.matchesLabel(asString(node.getContentDescription()));
    }

    private String asString(CharSequence value) {
        return value == null ? null : value.toString();
    }

    private void incrementSkipCount() {
        SharedPreferences preferences = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        int count = preferences.getInt(KEY_SKIP_COUNT, 0);
        preferences.edit().putInt(KEY_SKIP_COUNT, count + 1).apply();
    }

    private void endLaunchWindow() {
        launchWindowActive = false;
        launchWindowStartedAt = 0L;
        clickedInLaunchWindow = false;
    }

    private void clearTracking() {
        foregroundPackage = null;
        endLaunchWindow();
        hasScanned = false;
        lastScanAt = 0L;
    }

    private boolean samePackage(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static final class NodeAtDepth {
        final AccessibilityNodeInfo node;
        final int depth;
        final boolean owned;

        NodeAtDepth(AccessibilityNodeInfo node, int depth, boolean owned) {
            this.node = node;
            this.depth = depth;
            this.owned = owned;
        }
    }
}
