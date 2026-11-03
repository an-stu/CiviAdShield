#!/bin/sh
set -eu

project_root=/Users/an/Public/Codes/test/CiviAdShield
label=cn.civi.adshield.source-sync
plist_path=${HOME:?HOME is required}/Library/LaunchAgents/${label}.plist
log_dir=${project_root}/.toolchain/sync
action=${1:-}

if [ "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)" != "$project_root" ]; then
    printf '%s\n' 'installer must run from the configured CiviAdShield project' >&2
    exit 2
fi

uid=$(id -u)
service_target="gui/${uid}/${label}"

case "$action" in
    install)
        if [ -e "$plist_path" ]; then
            printf '%s\n' 'LaunchAgent plist already exists; inspect it before replacing it.' >&2
            exit 1
        fi
        python_path=$(command -v python3 || true)
        git_path=$(command -v git || true)
        gh_path=$(command -v gh || true)
        if [ -z "$python_path" ] || [ -z "$git_path" ]; then
            printf '%s\n' 'python3 and git must be available on PATH.' >&2
            exit 1
        fi
        runtime_path=${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}
        for executable in "$python_path" "$git_path" "$gh_path"; do
            [ -n "$executable" ] || continue
            executable_dir=${executable%/*}
            case ":${runtime_path}:" in
                *":${executable_dir}:"*) ;;
                *) runtime_path=${executable_dir}:${runtime_path} ;;
            esac
        done
        mkdir -p "$(dirname -- "$plist_path")" "$log_dir"
        python3 - "$plist_path" "$project_root" "$python_path" "$runtime_path" "$label" <<'PY'
import plistlib
import sys
from pathlib import Path

plist_path, root, python_path, runtime_path, label = sys.argv[1:]
root_path = Path(root)
data = {
    "Label": label,
    "ProgramArguments": [python_path, str(root_path / "tools/live-sync.py")],
    "WorkingDirectory": root,
    "EnvironmentVariables": {"PATH": runtime_path},
    "RunAtLoad": True,
    "KeepAlive": True,
    "StandardOutPath": str(root_path / ".toolchain/sync/stdout.log"),
    "StandardErrorPath": str(root_path / ".toolchain/sync/stderr.log"),
}
Path(plist_path).write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=True))
PY
        chmod 600 "$plist_path"
        printf 'Created LaunchAgent plist: %s\n' "$plist_path"
        printf '%s\n' 'It is not started by install; run this script with start when ready.'
        ;;
    start)
        if [ ! -f "$plist_path" ]; then
            printf '%s\n' 'LaunchAgent plist is missing; run install first.' >&2
            exit 1
        fi
        launchctl bootstrap "gui/${uid}" "$plist_path"
        launchctl kickstart -k "$service_target"
        printf '%s\n' 'Source sync LaunchAgent started.'
        ;;
    stop)
        if launchctl bootout "$service_target" >/dev/null 2>&1; then
            printf '%s\n' 'Source sync LaunchAgent stopped.'
        else
            printf '%s\n' 'Source sync LaunchAgent is not loaded.'
        fi
        ;;
    status)
        if launchctl print "$service_target" >/dev/null 2>&1; then
            printf '%s\n' 'Source sync LaunchAgent is loaded.'
        else
            printf '%s\n' 'Source sync LaunchAgent is not loaded.'
        fi
        python3 "$project_root/tools/live-sync.py" --status
        ;;
    uninstall)
        if launchctl bootout "$service_target" >/dev/null 2>&1; then
            :
        fi
        if [ -f "$plist_path" ]; then
            rm "$plist_path"
        fi
        printf '%s\n' 'Source sync LaunchAgent plist removed.'
        ;;
    *)
        printf 'Usage: %s {install|start|stop|status|uninstall}\n' "$0" >&2
        exit 2
        ;;
esac
