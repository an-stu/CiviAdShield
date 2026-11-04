# v1.0.3 网络规则改进验证记录

日期：2026-11-04（Asia/Shanghai）。包名 `cn.civi.adshield`，versionName `1.0.3`，versionCode `4`，minSdk 26，compile/target SDK 35。沿用原项目签名。

## 真实贴吧帖子详情

使用官方贴吧 22.13.1.1（ARM64），在 Android 15 / API35 模拟器中未登录账号，进入公开帖子并连续下滑至回复区。通过正常“分享→复制链接”固定同一帖子；各轮清除模拟器内贴吧数据并重复相同隐私选择，减少应用缓存影响。生产净屏没有无障碍服务，未安装 CA，也未接管默认链接。

| 样本 | 实际画面 |
| --- | --- |
| 关闭过滤的首次基线 | 出现带“广告”标记的 50 元红包浮层、购物优惠推广回复和推广图片 |
| 开启 AdGuard DNS + anti-AD | 本轮未出现红包浮层；推广回复及图片仍然存在，普通帖子/回复正常加载 |
| 随后再次关闭过滤 | 本轮同样未出现红包浮层；推广回复及图片仍然存在 |

**红包浮层不是稳定复现样本，不能将其消失归因于过滤。帖子回复中的商业内容仍未屏蔽。** 不把 DNS 拦截请求数量解释为去除广告数量，也没有验证全局禁止广告跳转。

AdGuard 中文网页列表中的贴吧 DOM/CSS 规则依赖网页结构，不能在本应用的 DNS 层删除 Android 原生回复或卡片。当前实现没有集成 AdGuard 完整 HTTP(S) 过滤引擎。完整 AdGuard Android 应用的应用内过滤对照未完成，不以其效果为本应用背书。详见 [TIEBA.md](docs/TIEBA.md)。

原始贴吧截图、UI 树、公开帖子链接和第三方 APK 仅保存在本机 `.toolchain/`，不随仓库或 Release 发布。开发测试使用 Android 仪器 UI 快照读取动态页面，这不属于生产应用权限或功能。

## 规则和更新

- 内置官方 AdGuard DNS 原始完整列表，SHA256 和 GPL-3.0 许可见 [第三方说明](THIRD_PARTY_NOTICES.md)。本次快照可执行 187396 条，忽略 940 条不支持规则，1 条被 badfilter 禁用。
- 保留支持的例外、important、badfilter 语义；不支持的规则整行忽略，不剥除网址路径、修饰符、CSS、JS 或正则来制造域名规则。
- 合并用户白名单、自定义阻断、AdGuard DNS、anti-AD；用户白名单最高优先。原查询获得明确放行时，不再单独因别名阻断。
- 检查与原问题相关的 IN CNAME 回答链；拒绝畸形长度、循环及冲突别名，不使用无关回答污染规则判断。
- 已实际点击“更新 AdGuard DNS 规则”，通过平台 HTTPS 成功下载官方列表，显示 187396 条可执行规则、940 条忽略规则。更新是用户主动操作。

## 构建和设备回归

Java 单元测试 40 项通过，覆盖域名规则、AdGuard 例外/优先级/禁用规则、组合策略、CNAME 链及协议异常。Android Lint：0 错误，3 条工具/SDK 提示。发布 APK 沿用 RSA3072 证书，SHA256 指纹：

`d504ff6cb479a7267f003f387c2676dec60b9536744e08b7e5b6d485c89dd096`

设备与工具最终结果见下表和 `docs/emulator-results/release-1.0.3/`。完整日志保持本机私有。

| 检查 | 结果 |
| --- | --- |
| Android 15 / API35 ARM64，签名 v1.0.3 | GUI/网络 25/25，Release 仪器 27/27 |
| Android 16 / API36 ARM64，签名 v1.0.3 | GUI/网络 25/25，Release 仪器 27/27 |
| Java 单元测试 | 40/40，0 失败/错误/跳过 |
| Python 同步与 PCAP 工具测试 | 20/20 |
| 生产应用 Android Lint | 0 错误，3 条提示 |

GUI 检查包括真实 VPN/通知授权、UDP A/AAAA 与 TCP DNS、本地规则阻断、正常转发、自定义规则、白名单、暂停恢复联网、生产包无无障碍声明及无崩溃。仪器检查覆盖 VPN 路由与三次重启生命周期、导出例外和无效指定应用不会退化为全局 VPN。

## 兼容与权限

[COMPATIBILITY.md](docs/COMPATIBILITY.md) 记录 Android 8.0+ 通用 API 目标。Android 15/16 AOSP 模拟器不能替代小米真机验证；未连接 Civi5Pro / HyperOS 3.0.303.0，不宣称已覆盖所有 Xiaomi 系统与手机。

所需权限见 [PERMISSIONS.md](PERMISSIONS.md)：VPN 连接授权、网络和前台服务，通知建议允许。本版未增加无障碍、Root、Shizuku、悬浮窗、默认链接或 CA 权限。Clash Meta 使用时须暂停净屏或将域名规则交由 Clash。

## 复现

```sh
./tools/emulator.sh
./tools/emulator36.sh
./tools/package.sh
./tools/build.sh :test-fixture:assembleDebug
python3 tools/emulator-e2e.py --serial emulator-5554 --apk dist/CiviAdShield-1.0.3.apk --output .toolchain/reproduce35
python3 tools/emulator-e2e.py --serial emulator-5556 --apk dist/CiviAdShield-1.0.3.apk --output .toolchain/reproduce36
python3 tools/run-release-instrumentation.py --serial emulator-5554 --output .toolchain/instrumentation35.txt
python3 tools/run-release-instrumentation.py --serial emulator-5556 --output .toolchain/instrumentation36.txt
python3 -m unittest discover -s tests -p 'test_*.py'
```

设备脚本拒绝真实手机，并清理模拟器中的净屏及测试应用数据。仪器脚本使用本机签名，源码不携带密钥。v1.0.2 的吧页/网络样本属于历史结果，未被当作本次帖子详情的广告去除证据。
