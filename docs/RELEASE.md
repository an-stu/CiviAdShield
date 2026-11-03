# GitHub 自动构建与发布

仓库：https://github.com/an-stu/CiviAdShield（公开）。手机可从 Releases 下载 APK 手动覆盖安装。本应用不内置更新令牌，也不自动安装 APK。

## 工作方式

- 推送 `main`：云端运行单元测试、Lint，构建使用项目原签名的 APK。
- 版本号尚未发布时，自动创建 `v版本号` 的 GitHub Release，附 APK、SHA256 校验和、版本/签名元数据。
- 相同版本已有 Release 时，保留已发布附件；当前提交的签名 APK 仍可在 Actions 的构建附件中下载。不同版本不要重复使用同一个 versionCode。
- Pull Request 只做检查，不接触签名密钥或发布权限。
- GitHub Actions 页面支持手动运行 `Android build and release`，仅主分支允许签名与发布。

## 发布下一个版本

1. 先完成代码和测试，可在 `docs/releases/v1.0.3.md` 写本次发布说明。
2. 最后修改 `app/build.gradle` 的 `versionName`（例如 `1.0.3`）与递增的 `versionCode`（例如 `4`），表示这个版本可以发布。
3. 将变更同步到 `main`，等待 Actions 成功。若启用本机自动同步，保存文件并保持电脑联网即可。
4. 在 [Releases](https://github.com/an-stu/CiviAdShield/releases) 下载新 APK，手机手动覆盖安装。

手机覆盖安装要求签名一致。现有签名的加密副本存放在 GitHub Actions Secrets：`ANDROID_KEYSTORE_BASE64`、`ANDROID_STORE_PASSWORD`、`ANDROID_KEY_PASSWORD`、`ANDROID_KEY_ALIAS`。密钥不进入 Git 历史、源码包或 Release；本机原件保留于忽略的 `.signing/`，应单独备份。

工作流固定检查当前应用签名证书 SHA256；换用其他密钥会使构建失败，避免生成无法覆盖升级的 APK。已发布版本保持原样，后续修复请提高版本号。

若构建期间主分支又收到新提交，旧提交只保留构建附件，由新的主分支构建决定发布，避免实时同步过程中发布过时的提交。

本地源码同步及停止方式见 [SYNC.md](SYNC.md)。仓库中的模拟器验收报告属于已记录版本的本地测试，云端工作流不会把这些历史截图作为新版本的设备测试结果。
