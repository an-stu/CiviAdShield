package cn.civi.adshield.fixture;

import android.app.Activity;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.TextView;

/** A controlled splash UI for exercising the opt-in accessibility skip behavior. */
public final class SplashFixtureActivity extends Activity {
    public static final String EXTRA_SCENARIO = "scenario";

    private static final String PREFS_NAME = "fixture";
    private static final long LATE_BUTTON_DELAY_MS = 9_500L;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Runnable showLateButton = new Runnable() {
        @Override
        public void run() {
            if (!isFinishing() && root != null && targetButton == null) {
                addTargetButton("跳过广告", true, false, true);
                statusText.setText("延迟按钮已显示");
            }
        }
    };

    private FrameLayout root;
    private TextView statusText;
    private Button targetButton;
    private String scenario;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        scenario = allowedScenario(getIntent() == null
                ? null : getIntent().getStringExtra(EXTRA_SCENARIO));
        getWindow().setStatusBarColor(Color.rgb(244, 247, 244));
        getWindow().setNavigationBarColor(Color.rgb(25, 55, 47));
        configureEdgeInsets(getWindow());

        root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(244, 247, 244));
        installInsets(root);
        setContentView(root);

        TextView scenarioText = new TextView(this);
        scenarioText.setText("测试场景：" + scenario);
        scenarioText.setTextColor(Color.rgb(23, 54, 47));
        scenarioText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        FrameLayout.LayoutParams scenarioParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP | Gravity.LEFT);
        scenarioParams.leftMargin = dp(20);
        scenarioParams.topMargin = dp(24);
        root.addView(scenarioText, scenarioParams);

        TextView adMessage = new TextView(this);
        adMessage.setText("模拟广告页面");
        adMessage.setTextColor(Color.rgb(23, 54, 47));
        adMessage.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        FrameLayout.LayoutParams messageParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER);
        root.addView(adMessage, messageParams);

        statusText = new TextView(this);
        statusText.setText("等待测试操作");
        statusText.setTextColor(Color.rgb(74, 92, 84));
        statusText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        FrameLayout.LayoutParams statusParams = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER_HORIZONTAL | Gravity.BOTTOM);
        statusParams.bottomMargin = dp(36);
        root.addView(statusText, statusParams);

        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit()
                .putLong("launch_ms_" + scenario, SystemClock.elapsedRealtime())
                .apply();
        configureScenario();
    }

    @Override
    protected void onDestroy() {
        mainHandler.removeCallbacks(showLateButton);
        root = null;
        targetButton = null;
        super.onDestroy();
    }

    private void configureScenario() {
        if ("late_button".equals(scenario)) {
            statusText.setText("目标按钮将在 9.5 秒后出现");
            mainHandler.postDelayed(showLateButton, LATE_BUTTON_DELAY_MS);
            return;
        }

        if ("nonclickable_label".equals(scenario)) {
            addNonclickableLabel("跳过广告");
            return;
        }

        String label;
        switch (scenario) {
            case "english":
                label = "Skip ad 5s";
                break;
            case "negative_label":
                label = "跳过登录";
                break;
            case "disabled_button":
                label = "跳过广告";
                break;
            case "repeat_button":
                label = "跳过广告";
                break;
            default:
                label = "跳过广告 5秒";
                break;
        }

        boolean bottomRight = "negative_location".equals(scenario);
        boolean enabled = !"disabled_button".equals(scenario);
        addTargetButton(label, enabled, bottomRight, false);
    }

    private void addTargetButton(String label, boolean enabled, boolean bottomRight,
                                 boolean isLate) {
        if (root == null) {
            return;
        }
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        button.setTextColor(Color.WHITE);
        button.setAllCaps(false);
        button.setSingleLine(true);
        button.setIncludeFontPadding(false);
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
        button.setPadding(dp(6), dp(3), dp(6), dp(3));
        button.setMaxWidth((int) (getResources().getDisplayMetrics().widthPixels * 0.40f));
        button.setMaxHeight((int) (getResources().getDisplayMetrics().heightPixels * 0.10f));
        button.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(19, 124, 101)));
        button.setEnabled(enabled);
        button.setOnClickListener(view -> recordClick(isLate));

        int gravity = Gravity.RIGHT | (bottomRight ? Gravity.BOTTOM : Gravity.TOP);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                gravity);
        params.rightMargin = dp(12);
        if (bottomRight) {
            params.bottomMargin = dp(18);
        } else {
            params.topMargin = dp(8);
        }
        targetButton = button;
        root.addView(button, params);
    }

    private void addNonclickableLabel(String label) {
        TextView text = new TextView(this);
        text.setText(label);
        text.setTextColor(Color.rgb(23, 54, 47));
        text.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        text.setPadding(dp(6), dp(3), dp(6), dp(3));
        text.setClickable(false);
        text.setEnabled(true);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.RIGHT | Gravity.TOP);
        params.rightMargin = dp(12);
        params.topMargin = dp(8);
        root.addView(text, params);
    }

    private void recordClick(boolean isLate) {
        SharedPreferences preferences = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String clickKey = "clicks_" + scenario;
        int clicks = preferences.getInt(clickKey, 0) + 1;
        preferences.edit()
                .putInt(clickKey, clicks)
                .putBoolean("clicked_" + scenario, true)
                .apply();

        if ("repeat_button".equals(scenario)) {
            statusText.setText("同一按钮点击次数：" + clicks);
            return;
        }
        if (targetButton != null) {
            targetButton.setVisibility(View.GONE);
        }
        statusText.setText(isLate ? "延迟目标已点击" : "内容页面 · 已跳过");
    }

    private String allowedScenario(String requested) {
        if ("positive".equals(requested) || "english".equals(requested)
                || "negative_label".equals(requested)
                || "negative_location".equals(requested)
                || "late_button".equals(requested)
                || "disabled_button".equals(requested)
                || "nonclickable_label".equals(requested)
                || "repeat_button".equals(requested)) {
            return requested;
        }
        return "positive";
    }

    private void configureEdgeInsets(Window window) {
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false);
        } else {
            window.getDecorView().setSystemUiVisibility(
                    View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                            | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                            | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        }
    }

    private void installInsets(final View view) {
        view.setOnApplyWindowInsetsListener((target, insets) -> {
            int left;
            int top;
            int right;
            int bottom;
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                left = bars.left;
                top = bars.top;
                right = bars.right;
                bottom = bars.bottom;
            } else {
                left = insets.getSystemWindowInsetLeft();
                top = insets.getSystemWindowInsetTop();
                right = insets.getSystemWindowInsetRight();
                bottom = insets.getSystemWindowInsetBottom();
            }
            target.setPadding(left, top, right, bottom);
            return insets;
        });
    }

    private int dp(float value) {
        DisplayMetrics metrics = getResources().getDisplayMetrics();
        return (int) (value * metrics.density + 0.5f);
    }
}
