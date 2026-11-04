# 第三方说明

本仓库应用代码采用 MIT 许可，完整文本见 [LICENSE](LICENSE)。随应用分发的第三方规则数据保留各自许可，不随应用代码的 MIT 许可重新授权。

## AdGuard DNS filter

- 项目：[AdGuardTeam/AdGuardSDNSFilter](https://github.com/AdguardTeam/AdGuardSDNSFilter)
- 官方完整规则文件：https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
- 随包文件：`app/src/main/assets/filters/adguard-dns.txt`
- 许可：GPL-3.0；完整许可文本随 APK 包含于 `app/src/main/assets/licenses/ADGUARD-DNS-GPL-3.0.txt`
- 随包快照获取日期：2026-11-04（Asia/Shanghai）；文件元信息见 `app/src/main/assets/filters/adguard-dns-meta.json`
- 快照 SHA256：`b948c12b7bd42ae0e44476d6a65048955b4c79d707ff59937c8ada5eaa16952a`
- 该快照由本应用解析出 187,396 条可执行规则，忽略 940 条不支持的规则；手动更新后数量可能变化。

完整官方列表随 APK 分发。应用只执行支持的 DNS 域名规则；不支持的规则行保持原样但不会执行，也不会通过去除修饰符或转换规则来尝试执行。

## anti-AD

内置规则 `app/src/main/assets/anti-ad-domains.txt` 来源：

- 项目：privacy-protection-tools/anti-AD
- 地址：https://github.com/privacy-protection-tools/anti-AD
- 下载源：https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt
- 本地获取日期：2026-11-03（Asia/Shanghai）
- 文件自报版本：20261102061401
- 文件自报条数：109387
- SHA256：`a70eba1923fcc7159bf8f431c031365f06a34b73e4ce95d4278aa3992811b42a`
- 许可：MIT，完整文本随 APK 包含于 `app/src/main/assets/ANTI-AD-LICENSE.txt`

内置 anti-AD 列表保持下载原样。规则仅作为域名过滤数据使用，不代表能覆盖所有应用广告；上游规则可能产生误拦截。

Gradle Wrapper / Gradle：Apache License 2.0（https://github.com/gradle/gradle/blob/master/LICENSE）。Android 工具链依据 Google/Android SDK 自身许可安装，未包含在源码 ZIP 或 APK 中。JUnit 4.13.2 和 Hamcrest 1.3 仅用于开发测试，不打包进入应用。
