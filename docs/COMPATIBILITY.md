# 小米设备与系统兼容范围

净屏使用 Android 通用 `VpnService`、通知和标准设置接口，最低 Android 8.0 / API26。界面与设置面向小米、Redmi、POCO，不再以 Civi 5 Pro 为唯一展示对象，也没有机型白名单。APK 为纯 Java，没有 CPU 架构限定的本地库。

这属于兼容目标，**不等于已验证所有小米手机或所有 MIUI/HyperOS 版本**。Android 7.x 及更早系统不在当前安装范围内。

| 平台 | 验证方式 | 范围 |
| --- | --- | --- |
| Android 8.0 / API26 | minSdk、API 条件分支与 Lint 静态检查 | 未进行设备运行验证 |
| Android 15 / API35 ARM64 | AOSP 模拟器 | 官方贴吧启动/公开吧页网络样本、DNS 拦截、正常内容、无障碍关闭 |
| Android 16 / API36 ARM64 | AOSP 模拟器 | DNS/授权/白名单/启动停止等协议与界面验收，结果见 VALIDATION.md |
| MIUI / HyperOS 真机 | 未连接设备 | 后台清理、省电、分身/用户空间、厂商 VPN 菜单待真机验证 |

系统差异处理：

- Android 13+ 在需要时请求通知权限；旧系统不请求此权限。
- Android 14+ 声明特殊用途前台服务；VPN 由用户主动启动。
- 使用标准应用信息、省电设置入口；不同 MIUI/HyperOS 的自启动或“不限制”菜单请在系统内按需配置。
- 内容视口处理系统栏 Insets，避免按钮落入状态栏/导航栏区域。
- VPN 作用于当前 Android 用户/配置；其他用户空间、工作资料和分身不作跨用户保证。
- 同时只能使用一个 VPN；使用 Clash Meta 时暂停净屏或将域名规则交给 Clash。
- 重启手机后手动开启过滤。系统强行停止进程会结束过滤，应用不能绕过系统后台管理。

不需要无障碍、Root、Shizuku 或默认浏览器角色。网络和广告机制的限制见 README.md，真实贴吧结果见 [TIEBA.md](TIEBA.md)。
