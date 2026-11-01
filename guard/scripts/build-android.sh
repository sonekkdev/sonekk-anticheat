#!/usr/bin/env bash
# Builds libsonekk_guard.so for standalone Android VR headsets.
set -euo pipefail

: "${ANDROID_NDK:?Set ANDROID_NDK to your NDK directory}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/native/build-android"

cmake -S "$ROOT/native" -B "$BUILD" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-29 \
  -DCMAKE_BUILD_TYPE=Release \
  -DANDROID_STL=c++_static

cmake --build "$BUILD" --target sonekk_guard

shopt -s nullglob
for so in "$BUILD"/*.so; do
  echo "built: $so"
  echo "copy it to Assets/Plugins/Android/libs/arm64-v8a/"
done
