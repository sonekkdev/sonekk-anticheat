#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== native =="
cmake -S "$ROOT/native" -B "$ROOT/native/build" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/native/build"
ctest --test-dir "$ROOT/native/build" --output-on-failure

echo "== server =="
node --test "$ROOT/server/test/guard.test.js"
