#!/bin/sh
set -eu
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAVA_HOME=${JAVA_HOME:-/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home}
ANDROID_HOME="$PROJECT_ROOT/.toolchain/android-sdk"
ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME ANDROID_HOME ANDROID_SDK_ROOT
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
if [ "$#" -eq 0 ]; then
  set -- assembleDebug
fi
exec "$PROJECT_ROOT/gradlew" "$@"
