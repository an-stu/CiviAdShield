# 净屏 · Xiaomi 网络广告拦截

面向小米、Redmi、POCO 的 Android 8.0+ 网络过滤应用。仅提供 DNS 网络过滤，**不使用无障碍、不自动点击广告、不接管默认链接、不安装 CA 证书或解密 HTTPS，也不需要 Root**。采用 Android 通用 VPN 接口，不按 Civi 5 Pro 或其他单一机型锁定。

[公开仓库](https://github.com/an-stu/CiviAdShield) · [下载 APK](https://github.com/an-stu/CiviAdShield/releases) · [权限说明](PERMISSIONS.md) · [贴吧实测](docs/TIEBA.md) · [兼容范围](docs/COMPATIBILITY.md)

## 能做什么

- 使用本地 DNS VPN 阻断广告、跟踪及广告落地域名的解析请求。
- 内置 anti-AD 规则，支持自定义域名、hosts 导入和优先白名单。
- 默认过滤全部应用；可选择仅过滤指定应用，或者排除应用。修改范围后需暂停并重新启动过滤。
- 最近被拦截域名和累计次数保存在本机；支持导出 Clash Meta / mihomo 域名规则。
- 提供标准应用信息、省电设置和 Android 版本信息入口，适配不同 MIUI / HyperOS 的菜单差异。

## 效果边界

DNS 无法区分同一域名/接口内的正常内容和广告，也无法删除已缓存或客户端绘制的广告卡片。自带安全 DNS、硬编码 IP、缓存解析可能绕过本应用。**本应用不能在系统层全局禁止其他应用显式拉起应用**；按用户选择，不提供默认链接接管。

实际安装了官方贴吧 22.13.1.1，在 Android 15 ARM64 模拟器滚动查看公开帖子详情时，未过滤基线曾看到明确标注的 50 元红包悬浮广告；随后同一帖子在过滤样本和再次关闭过滤的复查中都没有该悬浮广告，无法确认它消失是否由过滤导致。过滤时商业/优惠类回复及配图仍然存在。DNS 不能区分同域名接口中的广告和正常内容。详见 [贴吧实测](docs/TIEBA.md)。

## 安装使用

1. 在 [Releases](https://github.com/an-stu/CiviAdShield/releases) 下载 APK，传到手机安装；允许用于打开 APK 的文件管理器安装应用。
2. 打开净屏，点击“开启域名拦截”，阅读说明并同意系统 VPN 授权；建议允许通知以查看状态和暂停操作。
3. 测试时将系统“私人 DNS”设为关闭，检查目标应用是否自行启用了安全 DNS。
4. 若只测试贴吧，选择“仅拦截指定应用”并勾选贴吧，再暂停、重新开启。保存仅指定列表会清空排除列表；保存排除列表会恢复全局模式。
5. 出现登录或内容加载异常，先暂停过滤确认关联，再查看近期拦截、添加白名单或排除应用。DNS 缓存失效可能需要等待或重新打开目标应用。
6. MIUI / HyperOS 如清理后台，可在应用信息中按需允许后台运行、自启动、通知并调整省电策略。本版本不自动开机启动；手机重启后请手动开启。

不需要 Root、Shizuku、无障碍、悬浮窗或存储访问权限。

## Clash Meta

同一 Android 用户同时只有一个 VPN。使用 Clash 时暂停净屏，并按 [CLASH.md](CLASH.md) 将导出规则交由 Clash 执行。仅指定/排除应用范围不会写入域名规则集，应用分流应在 Clash 中配置。

## 隐私和规则

没有广告 SDK、统计 SDK、账户服务、远程 VPN、截图、界面读取、CA 安装或 HTTPS 解密。普通 DNS 默认明文发送至 `223.5.5.5`，失败回退 `119.29.29.29`；可自定义 IPv4 DNS，自定义地址不回退。上游及网络路径相关方可能观察查询域名。

仅保存规则、范围、设置和累计次数；最多 60 个近期被拦截域名留在进程内存。导入/导出使用系统文件选择器，关闭云备份和设备迁移。

内置官方 AdGuard DNS 完整规则文件，首次安装可离线使用。更新由用户手动启动，不会自动联网刷新；“规则来源与开关”可分别启用或停用 AdGuard DNS 与 anti-AD。也可用“导入 AdGuard DNS 列表”导入本地规则文件，仅执行支持的 DNS 域名规则，并替换 AdGuard DNS 订阅；自定义规则和白名单保留。AdGuard DNS 解析器支持纯域名行、`||domain^`、`*.domain`、`@@` 例外及 `$important`、`$badfilter`；AdGuard 导入不会解析 hosts 地址行。需要导入 hosts 文件时，使用单独的“导入域名 / hosts 规则”作为自定义来源。含不支持修饰符的规则行会整体忽略；网址路径、正则、CSS 和 JS 规则也会整体忽略，不会被剥除或转换。当前随包版本解析出 187,396 条可执行规则、忽略 940 条；官方更新后数量可能变化。规则与代码许可分别见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 构建与验证

JDK 17、Gradle 8.14.3、AGP 8.12.0、compile/target SDK 35、minSdk 26。纯 Java 应用，没有按手机 CPU 架构限定的本地库。

```sh
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
./tools/package.sh
```

本机 SDK 位于 `.toolchain/android-sdk`，可使用 `tools/build.sh`；本机测试依赖缓存可通过 `-PciviTestLibs=.toolchain/test-libs` 使用。其他电脑配置自己的 `local.properties` 或 ANDROID_HOME。签名密钥保留在忽略的 `.signing/`，源码包不含密钥。

GitHub 提高 `versionName` 和 `versionCode` 后自动构建、签名并发布新版本，手机手动下载覆盖安装。工作方式见 [自动发布](docs/RELEASE.md)，本机同步与停止方式见 [源码同步](docs/SYNC.md)。

[当前验证报告](VALIDATION.md) 区分真实贴吧场景、受控协议测试和未测范围；v1.0.1 的无障碍相关截图/测试仅为历史记录，不代表当前版本功能。
