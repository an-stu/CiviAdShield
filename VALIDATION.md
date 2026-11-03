# v1.0.2 网络版验证记录

日期：2026-11-03（Asia/Shanghai）。包名 `cn.civi.adshield`，versionName `1.0.2`，versionCode `3`，minSdk 26，compile/target SDK 35。沿用原项目签名。

## 实际测试分层

| 项目 | 结果 |
| --- | --- |
| 真实官方贴吧 22.13.1.1 | 启动/公开“小米吧”页面及 DNS 场景已运行；见 docs/TIEBA.md |
| Android 15 / API35 ARM64 模拟器 | 25 项网络版 GUI/网络检查通过；最终版 27 项同证书仪器检查通过 |
| Android 16 / API36 ARM64 模拟器 | 网络版候选构建的 25 项 GUI/网络检查通过；最终 v1.0.2 27 项同证书仪器检查通过 |
| 无障碍 | 生产 APK 无服务声明，系统开关关闭，网络过滤仍通过 |
| 无效的仅指定应用 | 明确停止，不回退为全局 VPN；选择界面可清除已卸载项 |
| Java 协议/规则测试 | 21/21 通过 |
| Python 工具测试 | 20/20 通过（同步 11、PCAP 解析 9） |
| 生产 Android Lint | 0 错误、3 条工具/SDK 版本提示；发布关键检查通过 |
| 发布签名 | 原 RSA3072 证书 / APK v2，SHA256 指纹保持不变 |

平台证据保存在 `docs/emulator-results/release-1.0.2/api35/` 和 `api36/`：`results.json`、`instrumentation.txt` 及本应用截图。Android16 的完整 GUI 检查使用网络版候选构建；最终版另完成协议/生命周期/无障碍缺失/无效范围检查和界面恢复检查。不把候选版本截图冒充新的独立广告样本。

## 真实贴吧结果

使用官方 Baidu 页面提供的 APK，签名验证通过；未登录个人账号。Launcher 显示登录入口，但 Manifest 声明的公开论坛 VIEW 路由可以正常打开“小米吧”。使用该入口检查公开帖子和图片。

仅过滤贴吧、无障碍关闭时，首次启动到公开吧页的本机拦截计数增加 84。对应的网络基线观察到 59 次命中列表的外发 UDP DNS 查询，过滤段外部抓包未见同类查询。具体域名及阶段解释见 [TIEBA.md](docs/TIEBA.md) 和脱敏 `summary.json`。

请求计数包含重试与跟踪，不是广告条数，也不计算拦截率。本次基线和过滤样本均未出现明确广告卡片，真实广告点击跳转没有可重复样本。因此没有把“贴吧信息流广告全部消失”或“所有广告跳转被禁止”判为通过。

原始 PCAP、贴吧 APK、完整论坛截图与日志只留本机 `.toolchain/tieba-tests/`，不上传第三方用户帖子或认证数据。

## 本次改动与回归

- 删除无障碍服务、自动点击代码、入口和相关权限配置；升级清理旧跳过偏好，保留规则与次数。
- 新增仅指定应用范围，与排除列表互斥；显式检查应用是否安装/启用，避免不同平台接受无效包名后仍显示运行。
- 选择列表过滤已卸载项，用户能恢复全部应用范围。
- 系统栏 Insets 作用于滚动视口，避免按钮落入导航栏；测试驱动也改为点击完全可见的控件。
- 面向小米、Redmi、POCO 使用标准应用信息/省电设置及设备版本信息，无型号白名单和厂商隐藏 API。
- 增加 PCAP UDP DNS 聚合工具及畸形数据、端序、链路层、压缩名、分片等测试。

仪器测试验证 UDP A/AAAA、本地 DNS TCP、正常转发、白名单、Clash 导出、VPN 授权/路由就绪、暂停及三次重启，另检查无障碍服务缺失和无效目标不会成为全局 VPN。测试 APK 由同证书签名，生产应用保持 Release 配置。

## 兼容目标和未测范围

[COMPATIBILITY.md](docs/COMPATIBILITY.md) 记录 Android 8.0+ 的通用 API 目标及 Android15/16 AOSP 验收。没有小米真机，不能宣称逐一验证所有手机和 MIUI/HyperOS 版本；Android7.x及以前不在范围。后台保活、分身/工作配置和厂商安全策略需真机验证。

DNS 不能区分同域/接口内的广告与正常内容，不能处理缓存、硬编码 IP 或所有自带安全 DNS，也不能全局拦截其他应用显式发起的跳转。按用户选择，不提供默认链接接管。

## 复现命令

```sh
./tools/emulator.sh
./tools/emulator36.sh
./tools/build.sh :test-fixture:assembleDebug
python3 tools/emulator-e2e.py --serial emulator-5554 --apk dist/CiviAdShield-1.0.2.apk --output .toolchain/reproduce35
python3 tools/run-release-instrumentation.py --serial emulator-5554 --output .toolchain/instrumentation35.txt
python3 tools/run-release-instrumentation.py --serial emulator-5556 --output .toolchain/instrumentation36.txt
python3 -m unittest discover -s tests -p 'test_*.py'
./tools/package.sh
```

设备脚本拒绝对真实手机执行，会清理模拟器中的净屏/测试应用数据。仪器脚本需要本机签名，不在源码包中携带密钥。旧版 v1.0.1 无障碍测试材料仅为历史记录。
