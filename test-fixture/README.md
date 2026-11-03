# Controlled Android test fixture

This separate, debug-only application provides a repeatable accessibility UI and independent DNS
probes. It has no ad SDK and is not part of the production `:app` APK.

## Build and install

```sh
./tools/build.sh :test-fixture:assembleDebug
adb install -r test-fixture/build/outputs/apk/debug/test-fixture-debug.apk
```

The launcher opens the positive Chinese scenario. A scenario can also be launched directly:

```sh
adb shell am start -n cn.civi.adshield.fixture/.SplashFixtureActivity --es scenario positive
```

Supported scenarios are `positive`, `english`, `negative_label`, `negative_location`,
`late_button`, `disabled_button`, `nonclickable_label`, and `repeat_button`. Click counts are
stored in the `fixture` preferences as `clicks_<scenario>` with a corresponding
`clicked_<scenario>` boolean. They persist between launches so a test can compare before and
after values.

## Network probes

The exported `NetworkProbeActivity` runs independently of production DNS classes:

```sh
adb shell am start -n cn.civi.adshield.fixture/.NetworkProbeActivity \
  --es host ad.xiaomi.com --es resolver 10.111.0.2 --es token before
```

It sends UDP A, UDP AAAA, and TCP A queries to port 53, then calls the system resolver for
`example.com`. Each network exchange has an eight-second timeout. The JSON report is stored in
the `fixture` preferences under `network_<token>`. On a debuggable install it can be read with:

```sh
adb shell run-as cn.civi.adshield.fixture cat shared_prefs/fixture.xml
```

Scenarios must be supplied through the `scenario` intent extra. Network probe extras are
`host`, `resolver` (IPv4 address), and `token`.
