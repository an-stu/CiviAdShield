# 与 Clash Meta / mihomo 配合

Android 每个用户同时只能运行一个 VPN 服务，所以使用 Clash 时，请暂停净屏的“广告域名拦截”；新版不提供无障碍自动跳过功能。净屏不会抢占或自动重启 VPN。

## 推荐：让 Clash 执行域名广告过滤

1. 在净屏中选择“导出 Clash 广告规则”，保存 `civi-ads.yaml`。文件是 `behavior: domain` 的规则集，**不是完整代理配置或订阅**。
2. 将它放到 Clash 客户端实际可读的配置目录，例如 `ruleset/civi-ads.yaml`。Android 文件选择器中的“下载”路径不一定是 Clash 核心配置目录；不同客户端的文件导入方式不同，需要通过该客户端支持的规则文件导入或配置管理功能操作。
3. 在现有配置的 `rule-providers:` 下合并下面的内容。若已有同名字段，请合并，不要重复创建 YAML 顶层键：

```yaml
rule-providers:
  civi-ads:
    type: file
    behavior: domain
    format: yaml
    path: ./ruleset/civi-ads.yaml
```

4. 在已有 `rules:` 中，放在宽泛的 DIRECT/代理放行规则和最终 MATCH **之前**：

```yaml
rules:
  - RULE-SET,civi-ads,REJECT
  # 保留你已有的其他路由规则和最终 MATCH
```

5. 重新加载 Clash 配置。打开常用应用检查登录、支付、视频；如有误拦截，在净屏中加白名单、重新导出，替换规则文件后重载。

导出会合并内置和自定义拦截域名。域名集无法直接表达“阻止父域名但放行某个子域名”，因此如果白名单中有子域名，导出时会省略拦截列表中的相关父域名；这可能扩大放行范围。净屏的“排除应用”不写入 Clash 导出，Clash 的应用分流应在 Clash 内配置。净屏无法自动替所有 Clash 客户端修改配置。

## 不方便导入本地文件时

可以在 Clash 配置中直接使用上游 anti-AD 的远程 provider。这样规则由 Clash 下载和更新；净屏白名单、自定义域名不会自动同步：

```yaml
rule-providers:
  anti-ad:
    type: http
    behavior: domain
    format: yaml
    path: ./ruleset/anti-ad.yaml
    url: https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml
    interval: 86400

rules:
  - RULE-SET,anti-ad,REJECT
  # 保留原有其他规则，不要用此片段覆盖订阅全文
```

订阅更新可能覆盖手工修改，请使用所用客户端支持的覆写/合并机制。远程列表的可达性取决于网络与客户端；此项目不修改你的现有 Clash 配置。

配置参考：[mihomo rule-providers](https://wiki.metacubex.one/config/rule-providers/)、[规则内容](https://wiki.metacubex.one/config/rule-providers/content/)、[anti-AD](https://github.com/privacy-protection-tools/anti-AD)。
