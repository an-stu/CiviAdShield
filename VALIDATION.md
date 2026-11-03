# v1.0.1 实际验证记录

日期：2026-11-03（Asia/Shanghai）。交付包为 `dist/CiviAdShield-1.0.1.apk`，包名 `cn.civi.adshield`，versionCode 2，最低 Android 8.0，target/compile SDK 35。

## 测试环境

已安装并实际启动 Google 官方 Android Emulator 37.2.13，使用 AOSP Android 15 / API 35 ARM64 镜像 revision 2。AVD 为项目本地的 `CiviAdShield35`，序列号 `emulator-5554`，1080×2400，density 420，Hypervisor.Framework 加速，`sys.boot_completed=1`。官方包校验和与启动方式见 SETUP-NOTES.txt。

所有设备操作均针对这个新建模拟器，没有连接或修改真实手机。界面截图已人工查看。

## 结果

| 验证项目 | 结果与证据 |
| --- | --- |
| 签名正式 APK 启动 | 通过，实际启动 v1.0.1，见 `docs/emulator-results/release-1.0.1-passed/01-launch.png` |
| 首次权限流程 | 通过应用内说明、系统 VPN 连接请求与通知授权弹窗，保留 `02-vpn-permission.png`、`02a-notification-permission.png` |
| 正式包端到端检查 | 35/35 通过，详见同目录 `results.json` |
| 签名正式包仪器测试 | 24/24 通过，详见同目录 `instrumentation.txt`；测试 APK 使用同一证书，目标应用保持 Release 配置 |
| 纯 Java 协议与规则单元测试 | 23/23 通过，0 失败、0 错误 |
| 生产应用 Android Lint | 通过，0 错误、4 条已审阅警告；发布关键检查通过；测试夹具另行 Lint 通过 |
| APK 签名 | `apksigner verify` 通过，RSA 3072 / APK Signature Scheme v2；沿用 v1.0.0 的项目签名 |

端到端执行目录：`docs/emulator-results/release-1.0.1-passed/`。其他尝试目录保留了排查时的证据，不作为最终通过记录。

### 广告域名拦截与网络

从独立的测试应用进程发送真实 UDP A、UDP AAAA 和 TCP A 查询，不调用生产应用的 DNS 编解码类：

- 内置规则中的 `ad.xiaomi.com`：三个查询均收到匹配 ID/问题的 NOERROR / 无答案响应。
- `example.com`：普通 A 查询与 TCP A 查询正常返回记录。
- 将 `example.com` 加入自定义拦截：三个查询均返回无答案；加入白名单后 A / TCP A 恢复返回记录。
- 点击暂停后，普通 DNS 和 Android 系统解析仍正常。仪器测试另验证暂停结束及三次重新建立、查询、停止，检查旧任务退出后新连接仍可工作。

当前宿主网络对 `example.com` 返回 `198.18.0.94`；测试使用响应格式与记录有无验证转发和过滤路径，没有将它当作公网权威地址验证。正常 AAAA 查询在这个网络中可合法返回无答案，因此普通 AAAA 断言检查合法响应；A 和 TCP A 必须确实有记录。

对应原始记录：`network-baseline.json`、`network-builtin-ad.json`、`network-normal.json`、`network-custom-block.json`、`network-whitelist.json`、`network-after-pause.json`。

### 开屏跳过

使用独立包 `cn.civi.adshield.fixture` 的受控界面验证真实跨应用点击。它不是生产 APK 的一部分，无广告 SDK、无生产代码依赖。

| 场景 | 实际结果 |
| --- | --- |
| 服务已启用，但未选择应用 | 0 次点击 |
| 已选择应用，右上角“跳过广告 5秒” | 1 次点击，按钮消失，显示“内容页面 · 已跳过” |
| 右上角 `Skip ad 5s` | 1 次点击 |
| 同一个可点击按钮保持显示 | 仅点击 1 次 |
| “跳过登录” | 0 次点击 |
| 正确文字，但按钮在底部 | 0 次点击 |
| 按钮已禁用 | 0 次点击 |
| 只有不可点击文字 | 0 次点击 |
| 按钮在进入前台 9.5 秒后出现 | 0 次点击 |
| 无障碍服务关闭 | 0 次点击 |

点击计数来自测试应用自己的 SharedPreferences，并在测试前后比较，结合实际截图检查。测量期间没有使用会干扰无障碍服务的 UIAutomation；截图使用 adb screencap。无障碍绑定状态见 `accessibility-bound.txt`，截图文件名为 `splash-*.png`。

## 实测发现并修复

1. **暂停未必真正关闭 VPN。** Android 仍绑定 VpnService 时，仅 `stopService()` 不保证触发销毁。改为发送明确的 STOP 请求，由服务关闭通道和工作线程后结束，释放 VPN。
2. **连续重启时，旧任务偶尔关闭新连接。** 为每次运行分配独立编号；读线程、TCP 端点、工作队列使用本次运行的对象；旧响应、旧异常和旧线程退出不能影响新运行。关闭时只中断该次运行的读线程。
3. **搜索应用后，保存按钮被键盘遮挡。** 调整应用选择列表高度与软键盘窗口模式，选择应用后自动收起键盘，提供“完成”操作并关闭包名搜索建议。正式包测试确认选择已实际保存，然后验证自动跳过。

仪器测试也补齐了 VpnService.prepare() 和 Android VPN 路由就绪等待；这些是测试前置条件。它不通过授予 Root 或修改生产规则来模拟成功。

## 权限

完整说明见 [PERMISSIONS.md](PERMISSIONS.md)。模拟器内已验证网络/网络状态/前台服务权限自动授予、通知权限允许、VPN 系统授权和无障碍绑定。排查时只用模拟器 shell 查看过本应用的偏好文件，生产应用保持免 Root，未授予它 Root 权限。

## 复现

```sh
./tools/emulator.sh
./tools/build.sh :test-fixture:assembleDebug
python3 tools/emulator-e2e.py --output docs/emulator-results/reproduce
python3 tools/run-release-instrumentation.py
./tools/package.sh
```

端到端脚本会清理本模拟器中净屏和测试应用的数据，拒绝对真实手机执行。仪器测试脚本需要本机 `.signing/` 中的项目签名，源码 ZIP 不包含密钥。

## 验证范围

已验证 Android 15 AOSP 模拟器中的启动、授权、DNS 过滤、白名单、暂停/重启，以及受控场景中的开屏跳过。没有用 HyperOS 3.0.303.0 真机或任意第三方商业应用的广告页面做覆盖率测试，没有安装 Clash Meta 本身。因此不能把本报告解释为所有广告都可清除、HyperOS 后台保活已验证，或所有应用的登录/支付/视频业务均已验收。

4 条 Lint 提示涉及固定的 SDK/Gradle 版本以及旧 Android 忽略 `isAccessibilityTool=false` 属性，不涉及未修复的 Lint 错误。
