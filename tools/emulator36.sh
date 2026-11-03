#!/bin/sh
set -eu
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SDK_ROOT="$PROJECT_ROOT/.toolchain/android-sdk"
AVD_HOME="$PROJECT_ROOT/.toolchain/avd"
USER_HOME="$PROJECT_ROOT/.toolchain/android-user36"
EMULATOR="$SDK_ROOT/emulator/emulator"
AVD_NAME=XiaomiAdShield36
if [ ! -x "$EMULATOR" ]; then
  echo "Android emulator is missing or not executable: $EMULATOR" >&2
  exit 1
fi
if [ ! -f "$AVD_HOME/$AVD_NAME.avd/config.ini" ]; then
  echo "Project-local AVD is not configured: $AVD_HOME/$AVD_NAME.avd/config.ini" >&2
  exit 1
fi
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export ANDROID_AVD_HOME="$AVD_HOME"
export ANDROID_USER_HOME="$USER_HOME"
export ANDROID_EMULATOR_HOME="$USER_HOME/emulator"
export PATH="$SDK_ROOT/platform-tools:$PATH"
exec "$EMULATOR" -avd "$AVD_NAME" -port 5556 \
  -no-window -no-audio -no-boot-anim -no-snapshot-save \
  -gpu swiftshader_indirect "$@"
