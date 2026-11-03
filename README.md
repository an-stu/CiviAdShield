# 净屏 · Civi Ad Shield

为 Xiaomi Civi 5 Pro、HyperOS 3.0.303.0 使用需求开发的免 Root Android 应用，最低 Android 8.0。当前版本 v1.0.1 已在 Android 15 ARM64 模拟器实际验证，不能保证清除所有广告；HyperOS 版本仍需要真机验证。

本次实测修复了暂停未释放 VPN、快速重启时旧任务影响新连接、应用选择界面的键盘遮挡。完整结果见 [VALIDATION.md](VALIDATION.md)，所需权限见 [PERMISSIONS.md](PERMISSIONS.md)。

GitHub 仓库：[an-stu/CiviAdShield](https://github.com/an-stu/CiviAdShield)（私有）。[下载 Releases](https://github.com/an-stu/CiviAdShield/releases) · [自动构建与发布说明](docs/RELEASE.md) · [本机实时同步](docs/SYNC.md)。

**直接屏蔽广告域名不需要无障碍。** 无障碍只用于可选的自动点击“跳过”按钮。当前版本没有全局禁止其他应用拉起应用的能力；与正常内容共用域名或接口的信息流广告也不能仅凭 DNS 区分。

## 安装使用

1. 将 `dist/CiviAdShield-1.0.1.apk` 传到手机后安装，按系统提示允许相应来源安装应用。
2. 打开“净屏”，点击“开启域名拦截”，阅读 DNS 上游说明并同意系统 VPN 授权。正常运行时会显示 VPN 图标和前台通知。
3. 按需在手机设置中搜索“私人 DNS”，先设为“关闭”进行过滤测试。第三方应用自带的 DoH/安全 DNS、硬编码 IP 可绕过过滤。
4. 要跳过开屏广告，先在“选择要跳过的应用”中勾选应用，再启用开关、手动授权“净屏 · 开屏跳过”无障碍服务。默认不选择任何应用。
5. 如果系统提示受限设置，在“应用信息”的更多菜单中寻找“允许受限设置”；HyperOS 的具体入口可能不同。需要时允许自启动、后台运行，调整省电策略，并在最近任务中锁定应用。
6. 查看“最近拦截”，点击误拦截域名加入白名单；或者在“不拦截这些应用”中排除应用，暂停并重新启动拦截以应用排除列表。

本版本不自动开机启动，不支持“始终开启 VPN”，以方便切换 Clash。手机重启或应用被强行停止后需要手动开启域名拦截。无障碍服务是否被系统恢复由系统管理，应用内有独立暂停开关。

## Clash Meta

净屏的域名过滤和 Clash 都使用 Android VPN 接口，不能同时运行。使用 Clash 前暂停净屏域名拦截；开屏跳过可以保持开启。可以导出 `civi-ads.yaml`，让 Clash 执行广告过滤。具体配置见 [CLASH.md](CLASH.md)。

## 已实现功能与边界

- 本地 DNS 过滤：只路由虚拟 DNS 地址 `10.111.0.2/32`，不接管正常网页、视频流量。支持 IPv4 UDP DNS、DNS-over-TCP 回退以及 AAAA 查询；其他 IPv6 流量直接使用原网络。
- 内置 anti-AD 中文域名列表（约 10.9 万条），支持纯域名、`0.0.0.0 / 127.0.0.1` hosts、`||domain^` 导入、自定义规则、白名单优先、应用排除、Clash 规则导出。
- 可选开屏跳过：只在手动选择的应用进入前台后 8 秒内，点击右上角可访问、可点击且明确写有“跳过”或“跳过广告”的按钮；不模拟坐标点击、返回或任意关闭按钮。图片按钮、自绘界面可能无法识别。
- 记录累计拦截/跳过次数，最多保留当前进程中的 60 个被拦截域名；不保存普通查询历史。

可以阻止使用独立广告域名的部分开屏、横幅、SDK 广告请求。与正常内容共用域名的广告、信息流广告、视频内嵌广告、缓存广告及绕过系统 DNS 的请求，可能无法处理。已有 DNS 和广告缓存可能导致规则修改后不立即生效。白名单会放行域名及全部子域名；不要随意放行宽泛域名。

如果某应用无法登录、支付或加载内容，先暂停域名拦截确认，再使用近期记录/白名单/应用排除定位。未匹配的 DNS 请求超时会返回 SERVFAIL，不会伪造成过滤成功。

## 隐私与网络

没有账户、分析、广告 SDK、远程 VPN 服务器、CA 证书安装、HTTPS 解密、截图或界面上传。无障碍权限完全可选，应用没有悬浮窗或读取短信权限。

默认将正常 DNS 查询明文发送到阿里 DNS `223.5.5.5`；失败时回退腾讯 DNS `119.29.29.29`。可自定义一个 IPv4 DNS 地址，自定义地址不自动回退。DNS 提供方和网络路径上的相关方可能看到这些域名。`usesCleartextTraffic=false` 不会将 UDP/TCP DNS 自动加密。

只在本机存储规则、设置、累计次数；被拦截域名仅在内存保留，关闭 Android 云备份。导入使用系统文件选择器，不申请宽泛存储权限。不会自动联网更新规则。更新方式：从规则来源下载新列表，通过“导入域名 / hosts 规则”替换自定义部分；规则来源及许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 构建

本机工具链在 `.toolchain/android-sdk`，Java 17 使用 Homebrew OpenJDK；不修改全局 shell 配置。标准 Gradle Wrapper 固定为 8.14.3，Android Gradle Plugin 8.12.0，compile/target SDK 35，Build Tools 35.0.0。

本机网络的 Java TLS 下载不稳定，额外准备了 `.toolchain/maven` 官方依赖缓存镜像和 `.toolchain/test-libs` 测试 JAR。需要时使用 `-PciviTestLibs=.toolchain/test-libs` 运行测试；`tools/package.sh` 会自动识别这些本机测试依赖。源码 ZIP 不包含这些可重新下载的缓存；网络正常的机器直接使用 Maven Central 即可。

```sh
./tools/build.sh testDebugUnitTest lintDebug assembleDebug assembleDebugAndroidTest
./tools/package.sh
```

`tools/package.sh` 首次生成专用于此项目的个人签名密钥，保存于 `.signing/`，然后运行测试、lint、发布构建和签名验证，输出 APK、源码 ZIP 和 SHA256 到 `dist/`。请备份 `.signing/`：更新 APK 必须使用同一签名。密钥和口令不会进入源码 ZIP。若重新生成密钥，手机上的旧版本不能直接覆盖升级。

在其他机器上构建：安装 JDK17、Android SDK command-line tools，安装 `platforms;android-35`、`build-tools;35.0.0`、`platform-tools`，写好自己的 `local.properties`（`sdk.dir=...`），再运行 `./gradlew testDebugUnitTest lintDebug assembleDebug`。`tools/build.sh` 默认使用本项目的本地 SDK，按需修改环境路径。

## 验证

协议单元测试覆盖 DNS 格式/响应校验、IPv4/UDP 长度/分片/校验和、域名边界/IDN/导入、开屏标签/位置和 DNS TCP 状态。模拟器集成 runner 会验证启动、UDP A/AAAA 拦截、TCP 拦截、正常解析、白名单、Clash 导出及停止。具体已运行结果见 [VALIDATION.md](VALIDATION.md)。

模拟器集成测试只在测试设备执行（不要替用户自动授权实机权限）：

```sh
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s emulator-5554 shell appops set cn.civi.adshield ACTIVATE_VPN allow
adb -s emulator-5554 shell am instrument -w cn.civi.adshield.test/cn.civi.adshield.SmokeInstrumentation
```

协议实现是轻量 DNS 端点，不是通用 TCP/IP 栈；TCP 连接每次处理一个 DNS 消息，状态数、队列与报文长度受限。应用不对外开放监听端口，不提供代理服务。

参考：[Android VPN](https://developer.android.com/develop/connectivity/vpn)、[无障碍服务](https://developer.android.com/guide/topics/ui/accessibility/service)、[mihomo 规则集合](https://wiki.metacubex.one/config/rule-providers/)。
