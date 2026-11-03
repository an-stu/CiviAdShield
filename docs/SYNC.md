# Local source sync

`tools/live-sync.py` watches the configured CiviAdShield checkout and pushes eligible local source edits to `origin/main`. It only runs for `/Users/an/Public/Codes/test/CiviAdShield`, on branch `main`, with `origin` pointing to `an-stu/CiviAdShield` over HTTPS or SSH. It does not initialize a repository, change Git configuration, create tags, or force-push. The daemon is local-to-remote: while idle it does not poll GitHub for remote changes.

The daemon polls every 2 seconds and waits until candidate files have had stable sizes and modification times for 8 seconds. It stages only the source allowlist below, checks candidate contents for private-key PEM headers and GitHub token prefixes, then creates commits with the message `chore: sync local source changes`. It checks `origin/main` before pushing. A clean checkout can fast-forward when the remote is ahead; if the remote has diverged or is ahead while local changes exist, the daemon leaves the worktree untouched and reports that a manual merge is needed.

## Files eligible for sync

The source roots are `app/`, `test-fixture/`, `gradle/wrapper/`, `tools/`, `.github/`, and `tests/`, restricted to `.java`, `.kt`, `.xml`, `.gradle`, `.properties`, `.py`, `.sh`, `.yml`, `.yaml`, `.md`, `.txt`, and `.bat` files. `docs/` contributes only direct `*.md` files. At the project root, the allowlist is `README.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `PERMISSIONS.md`, `VALIDATION.md`, `SETUP-NOTES.txt` when already tracked, `.gitignore`, `settings.gradle`, `build.gradle`, `gradle.properties`, `gradlew`, and `gradlew.bat`. The tracked `gradle/wrapper/gradle-wrapper.jar` is the only binary allowed.

Generated files and local state are excluded, including `.git`, `.gradle`, `.toolchain`, `.signing`, `dist`, `build`, `local.properties`, environment files, keys, certificates, PEM files, JKS files, and keystores. Other extensions such as APKs, images, runtime JSON, and logs are outside the allowlist. Text assets under `app/` are source data and can sync.

## Check and run

```sh
python3 tools/live-sync.py --status
python3 tools/live-sync.py --once --dry-run
```

`--status` reports the project root, branch, validation state, staged-change state, and candidate count without printing the remote URL. `--once --dry-run` validates eligible changes without staging, committing, fetching, or pushing. `--once` waits for candidate files to stabilize, then performs one actual sync pass and is an explicit auto-push action. When local files are clean, it also fetches `origin/main` and fast-forwards if the remote is ahead; use it to check for remote updates while the daemon is idle.

The LaunchAgent installer writes a new `~/Library/LaunchAgents/cn.civi.adshield.source-sync.plist`; `install` does not load or start it:

```sh
tools/install-sync.sh install
tools/install-sync.sh start
tools/install-sync.sh status
tools/install-sync.sh stop
```

The LaunchAgent starts at login and is kept alive. Its standard output and error logs are written under `.toolchain/sync/`. The process uses the existing Git credential helper or SSH agent; it does not put credentials in command arguments or logs. The installer refuses to replace an existing plist with the same label.

## Offline and manual recovery

When fetch or push fails or times out, the daemon logs one generic network error and waits a randomized 30–60 seconds before retrying. Git cannot prompt for credentials from the daemon. A successful local commit is retained for a later push attempt. When a merge, rebase, cherry-pick, staged change, wrong branch, or remote divergence is present, automatic syncing pauses rather than changing the index or resolving the conflict. Stop the LaunchAgent, resolve the Git state manually, and restart it when `--status` reports a clean `main` checkout. No automatic rebase or conflict resolution is performed.

Each successful source push may trigger the repository's configured CI or release workflows. Generated APKs and release archives remain outside this sync path.

## 本机已启用

本机已于 2026-11-03 安装并启用实时源码同步。保存代码后，文件稳定约 8 秒即自动提交并推送；电脑需处于登录、运行和联网状态。暂停：`./tools/install-sync.sh stop`；恢复：`./tools/install-sync.sh start`。修改版本号后，GitHub 将自动构建并发布新 Release，手机登录 GitHub 后手动下载更新。
