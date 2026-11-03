package cn.civi.adshield.core;

import java.util.Locale;
import java.util.regex.Pattern;

/** Pure matching and geometry rules for the optional splash-ad skip service. */
public final class SkipPolicy {
    private static final Pattern CHINESE_SKIP_COUNTDOWN = Pattern.compile(
            "^跳过\\s*\\d+(?:\\.\\d+)?\\s*(?:秒|s)?$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CHINESE_COUNTDOWN_SKIP = Pattern.compile(
            "^\\d+(?:\\.\\d+)?\\s*(?:秒|s)\\s*跳过$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CHINESE_SKIP_AD = Pattern.compile(
            "^跳过\\s*广告(?:\\s*\\d+(?:\\.\\d+)?\\s*(?:秒|s)?)?$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern ENGLISH_SKIP_AD = Pattern.compile(
            "^skip\\s+ad(?:\\s+\\d+(?:\\.\\d+)?\\s*(?:s|sec|secs|second|seconds)?)?$",
            Pattern.CASE_INSENSITIVE);

    private SkipPolicy() {
    }

    /**
     * Returns true only for a small set of exact skip-ad labels and countdown forms.
     * Generic "skip" labels and labels with additional actions are deliberately rejected.
     */
    public static boolean matchesLabel(String label) {
        if (label == null) {
            return false;
        }
        String normalized = label.trim().replaceAll("\\s+", " ");
        if (normalized.isEmpty()) {
            return false;
        }
        if ("跳过".equals(normalized) || "跳过广告".equals(normalized)) {
            return true;
        }
        String english = normalized.toLowerCase(Locale.ROOT);
        if ("skip ad".equals(english)) {
            return true;
        }
        return CHINESE_SKIP_COUNTDOWN.matcher(normalized).matches()
                || CHINESE_COUNTDOWN_SKIP.matcher(normalized).matches()
                || CHINESE_SKIP_AD.matcher(normalized).matches()
                || ENGLISH_SKIP_AD.matcher(english).matches();
    }

    /**
     * Returns whether a node is a small, fully contained target in the screen's upper-right
     * region. Coordinates and dimensions are in the same screen pixel space.
     */
    public static boolean allowedBounds(int left, int top, int right, int bottom,
                                        int screenWidth, int screenHeight) {
        if (screenWidth <= 0 || screenHeight <= 0) {
            return false;
        }
        long width = (long) right - left;
        long height = (long) bottom - top;
        if (width <= 0 || height <= 0) {
            return false;
        }
        return left >= screenWidth / 2.0
                && top >= 0
                && right <= screenWidth
                && bottom <= screenHeight * 0.30
                && width <= screenWidth * 0.45
                && height <= screenHeight * 0.15;
    }
}
