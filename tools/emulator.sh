#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SDK_ROOT="$PROJECT_ROOT/.toolchain/android-sdk"
AVD_HOME="$PROJECT_ROOT/.toolchain/avd"
EMULATOR="$SDK_ROOT/emulator/emulator"
AVD_NAME=CiviAdShield35

if [ ! -x "$EMULATOR" ]; then
  echo "Android emulator is missing or not executable: $EMULATOR" >&2
  exit 1
fi
if [ ! -f "$AVD_HOME/$AVD_NAME.avd/config.ini" ]; then
  echo "Local AVD is not configured: $AVD_HOME/$AVD_NAME.avd/config.ini" >&2
  exit 1
fi

export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export ANDROID_AVD_HOME="$AVD_HOME"
export ANDROID_USER_HOME="$PROJECT_ROOT/.toolchain/android-user"
export PATH="$SDK_ROOT/platform-tools:$PATH"

exec "$EMULATOR" -avd "$AVD_NAME" -port 5554 \
  -no-window -no-audio -no-boot-anim -no-snapshot-save \
  -gpu swiftshader_indirect "$@"
