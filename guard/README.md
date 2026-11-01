# Sonekk Guard

[![ci](https://github.com/sonekkdev/sonekk-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sonekkdev/sonekk-guard/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-PolyForm%20Small%20Business-blue)

Free anti-cheat for standalone VR, built for small studios that just want their game to stop getting modded.

Targets Quest and Pico class Android headsets. No kernel driver, no PC support, no telemetry service to sign up for.

**Free under the PolyForm Small Business license:** under 100 people and under 1M USD revenue, you can ship it in a commercial game at no cost. Larger studios need a commercial license.

## What it does

Runs inside your APK as a small native library. It looks for the things that actually let people mod a standalone VR game: root management, Frida, debuggers, patched libraries and changed function prologues. It produces a signed report, your server scores it, and your game decides what happens.

The client never decides a ban. That is deliberate: anything the client concludes can be patched out.

## Detections

| id | What it sees | Weight |
| --- | --- | --- |
| `frida.maps` | Frida agent, gadget, substrate or lsposed mapped into the process | 90 |
| `frida.thread` | Frida worker threads such as `gum-js-loop` | 85 |
| `frida.module` | The same, found in the loaded module list | 80 |
| `frida.port` | Frida's default listener on 27042 or 27043 | 70 |
| `frida.anon_exec` | Anonymous executable mappings that are not ART's JIT | 25 |
| `root.paths` | su binaries, Magisk, KernelSU, APatch, frida-server on disk | 60 |
| `root.mounts` | Magisk or adb style mounts in `/proc/self/mounts` | 45 |
| `root.props` | `ro.debuggable`, `ro.secure=0`, test-keys, unlocked bootloader | 35 |
| `debug.tracer` | `TracerPid` set, or a successful ptrace attach | 50 |
| `integrity.self_hash` | Your pinned library hash does not match | 95 |
| `integrity.symbol_hook` | A function prologue changed from the pinned baseline | 95 |
| `integrity.signature` | The APK signature is not the one you pinned | 90 |
| `app.debuggable` | The APK was built with `android:debuggable`, a repack smell | 15 |
| `integrity.memory_text` | Mapped code differs from the `.so` on disk, a runtime patch | 95 |
| `instrumentation.inconsistent` | A loaded library is missing from `/proc/self/maps`, a hooked view | 70 |
| `emulator.host` | QEMU or goldfish hardware props | 20 |

Thresholds, server side: 20 watch, 50 review, 100 block. Tune them, they are guesses until you have data.

## Report flow

```
client  ->  POST /v1/challenge        single use nonce, 2 minute TTL
client  ->  collect, sign HMAC        nonce is inside the signed body
server  ->  consume nonce, check HMAC, verify attestation if present
            chain to a pinned root, TEE challenge match, boot state and lock flags
server  ->  score findings, return verdict
```

A captured report cannot be replayed, because the nonce is burnt on first use.

## Quick start

**1. Build the native library** (needs the Android NDK, r25 or newer):

```bash
export ANDROID_NDK=$HOME/Android/Sdk/ndk/26.1.10909125
./scripts/build-android.sh
```

That produces `native/build-android/libsonekk_guard.so`. Copy it into your Unity project at:

```
Assets/Plugins/Android/libs/arm64-v8a/libsonekk_guard.so
```

**2. Install the Unity package**

Package Manager, Add package from disk, pick `unity/Packages/com.sonekk.guard/package.json`.

**3. Configure it**

Create the settings asset: right click in Project, Create, Sonekk Guard, Settings. Set your endpoint and a shared secret.

Drop `GuardRunner` on one GameObject in your first scene, assign the settings asset, and optionally pin your APK signature hash.

**4. Run the reference server**

```bash
cd server
SONEKK_GUARD_SECRET=your-secret npm start
```

Or deploy `server/src/app.js` inside your own backend. It is framework free and has no dependencies.

## Verified

- Native core builds with GCC 16 and passes 43 unit tests, including false positive guards for ART's JIT cache and stock `overlay` mounts, plus 300 rounds of malformed `/proc` fuzzing
- Server passes 24 tests: replay rejection, signature tampering, rate limiting, and real attestation chains generated with OpenSSL (valid chain accepted, wrong key rejected, untrusted root rejected, expired chain rejected)
- The report envelope is JSON with no device identifiers

**Not verified in this repository yet, be aware:**

- The Android `.so` was not built here, there is no NDK in this environment
- The Unity C# has not been compiled, there is no Unity install here
- The client side Keystore request is implemented but has never been compiled or run on a device
- Attestation tests use certificates generated with OpenSSL and a synthetic attestation extension, not a chain captured from real hardware
- Kernel level hiding (custom kernels, keybox spoofing) will beat every check here

## Why it is not unbypassable

On a device the player owns, nothing is. A determined modder will read this source, patch the library, and hook the collector. That is why the design does not depend on the client being honest:

- Scores and verdicts are computed on the server, from finding ids it recognizes
- A client that stops reporting is itself a signal
- The weights are tuned for "flag for review", not "auto ban"
- The useful long term lever is server authority plus behavioural statistics, not this library

Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) before you trust it with anything.

## Layout

```
native/     C++17 detection core, flat C API, host tests
unity/      Unity package, runtime only
server/     Reference report endpoint, Node, no dependencies
docs/       Threat model, integration, detection notes, privacy
```

## License

PolyForm Small Business 1.0.0. See [LICENSE](LICENSE).

Required Notice: Copyright 2026 sonekkdev (https://github.com/sonekkdev/sonekk-guard)
