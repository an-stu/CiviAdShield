# 网络拦截版需要的权限

| 权限/设置 | 是否需要 | 用途 |
| --- | --- | --- |
| VPN 连接授权 | 进行网络拦截必需 | 用户点击开启并同意系统连接请求。只路由本地 DNS 地址，不建立远程 VPN。 |
| 通知权限 | Android 13+ 建议允许 | 显示运行状态与暂停操作；拒绝通知不等于禁止前台服务。 |
| 网络访问、网络状态 | 安装时自动授予 | 转发正常 DNS 查询并选择可用网络。 |
| 前台服务及特殊用途前台服务 | 系统根据声明管理 | 保持用户主动启动的 DNS 过滤服务。 |
| 安装未知应用 | 安装 APK 时可能需要 | 授予用于打开 APK 的浏览器/文件管理器，不是净屏安装其他软件的权限。 |

**新版没有无障碍服务，不请求无障碍授权，不自动点击按钮。** 不需要 Root、Shizuku、默认浏览器角色、悬浮窗、宽泛存储权限或手机 USB 调试。历史版本的跳过偏好会在升级后清理，规则和拦截次数保留。

`BIND_VPN_SERVICE` 用于保护系统对 VPN 服务的绑定，不是需要用户通过 ADB 授予的权限。

MIUI / HyperOS 后台策略可能要求手动允许后台运行、自启动、通知或不限制省电。应用提供标准应用信息与省电设置入口，不会自行修改系统安全或省电设置。不同机型/系统菜单有所差异。

网络拦截不提供全局 Activity/Intent 拦截权限：它只能阻断经过本地解析器的已知广告目标请求，不能阻止其他应用不经网络直接启动一个应用页面。

模拟器测试中的 adb、抓包和界面操作仅用于验收，不是手机使用本应用所需权限。

参考：[Android VPN](https://developer.android.com/develop/connectivity/vpn)、[通知权限](https://developer.android.com/develop/ui/compose/notifications/notification-permission)、[Android 应用沙箱](https://source.android.com/docs/security/app-sandbox)。
