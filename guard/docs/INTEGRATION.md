# Integration

## Requirements

- Unity 2021.3 or newer, IL2CPP, arm64-v8a only
- Android NDK r25 or newer to build the native library
- Your own backend to hold the secret and store verdicts

## 1. Build the native library

```bash
export ANDROID_NDK=/path/to/ndk
./scripts/build-android.sh
```

Output: `native/build-android/libsonekk_guard.so`.

Copy it into your project:

```
Assets/Plugins/Android/libs/arm64-v8a/libsonekk_guard.so
```

In the Inspector for that file, enable **Android** and set the CPU to **ARM64**. Unity 2021 defaults to arm64 for Quest anyway, but check.

## 2. Install the package

Package Manager, plus button, **Add package from disk**, select:

```
unity/Packages/com.sonekk.guard/package.json
```

## 3. Settings asset

Right click in Project, **Create, Sonekk Guard, Settings**.

| Field | Meaning |
| --- | --- |
| endpoint | Base URL of your server, the runner posts to `endpoint + /v1/report` |
| apiKey | Shared secret used for the HMAC. Public by definition, it only stops spam |
| reportIntervalSeconds | 300 is fine. Each report costs a few milliseconds of background work |
| reportOnStart | Collect once at launch and log it, useful while integrating |
| expectedLibraryHash | Optional. SHA-256 of your built `libsonekk_guard.so` |
| requestAttestation | Ask the TEE for a certified key bound to the challenge. Needs trusted roots on the server |

## 4. Attach the runner

Add `GuardRunner` to a GameObject in your first scene, assign the settings asset.

If you pin your APK signature, put its SHA-256 in `pinnedSignatureSha256` on the component. Get it from:

```bash
keytool -printcert -jarfile app.apk
```

or from the Play Console. If you leave it empty, signature pinning is skipped and the check reports nothing.

## 5. Server

```bash
cd server
SONEKK_GUARD_SECRET=your-secret npm start
```

Then point `endpoint` at it. The reference server logs verdicts and nothing else. Use `onReport` in `createApp` to store what you need.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SONEKK_GUARD_SECRET` | empty | HMAC key. Empty disables signature checks |
| `SONEKK_REQUIRE_CHALLENGE` | `true` | Reject reports without a fresh nonce |
| `SONEKK_REQUIRE_ATTESTATION` | `false` | Reject clients without a valid attestation chain |
| `SONEKK_ATTESTATION_ROOTS` | empty | Path to a PEM bundle of trusted attestation roots |
| `PORT` | `8787` | Listen port |

The runner fetches a nonce from `/v1/challenge` before every report, so replay protection works out of the box. If you implement your own client, remember the nonce must be inside the signed body.

Attestation is optional and off by default because you need to supply roots. Drop the TEE root certificates for the devices you support into one PEM file and set `SONEKK_ATTESTATION_ROOTS`.

## 6. Decide what a verdict means

Do not ban in the client. A block verdict should do something boring: put the player in a shadow lobby, flag the account for review, or drop them from ranked.

## Pitfalls

- **Stripping.** If you strip the native library or rename it, `DllImport("sonekk_guard")` breaks. Keep the name.
- **Emulator.** Emulators trip several checks. Exclude development builds explicitly rather than lowering the weights.
- **Developer mode.** Normal on Quest. It is not a cheat signal and this library does not treat it as one.
- **Threading.** Collection touches the filesystem. `GuardRunner` runs it on a task and only the upload happens on the main thread.
- **Multiple installs.** The report contains no device id, so correlate with your own player id via the `player` field, which the runner appends when `playerId` is set.

## Testing detection without a cheater

The host test suite feeds real `/proc` formats into the analyzers:

```bash
cmake -S native -B native/build -G Ninja -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Release
cmake --build native/build
ctest --test-dir native/build --output-on-failure
```

Add fixtures in `native/tests/main.cpp` when you add a check. A detection you cannot test is a detection you cannot trust.
