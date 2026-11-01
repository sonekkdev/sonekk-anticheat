# Sonekk Seal 3

Manifest based APK integrity check for standalone VR fan games.

Kids do not need a PC mod loader to cheat a Quest game. They decompile the APK, drop `libmodmenu.so` into `lib/arm64-v8a`, patch `libil2cpp.so` or `classes.dex`, re-sign it with their own key and install it. Seal catches that by comparing the shipped APK against a manifest produced when you built it.

## Usage

Build time:

```bash
npx sonekk-seal sign build.apk -o seal.json
```

Ship `seal.json` with your server, then whenever a client connects:

```bash
npx sonekk-seal verify downloaded.apk --manifest seal.json
```

Exit code 1 means the APK was repacked: files added, removed or modified. Output names them.

```
entries: 6
does not match the build manifest
  unexpected: lib/arm64-v8a/libmodmenu.so
  known mod artefacts: lib/arm64-v8a/libmodmenu.so
```

## What it catches

- any added file, including injected native libraries and assets
- any removed file
- any modified file, detected by CRC and size, so an in place patch of `libil2cpp.so` shows up
- known mod artefact names even without a manifest

## How it works

Reads the APK as a ZIP and compares the central directory: names, CRCs, sizes. No Android tooling, no Java, no dependencies.

## Limits, read this

- It is an offline check. The client can always lie, so run it server side on the APK you receive or pair it with Sonekk Guard and attestation for the on device verdict.
- Signature pinning is not implemented yet. Manifest comparison is usually stronger anyway, because a repack always changes the archive.
- CRC is not a cryptographic hash. A determined attacker can craft a collision. The next step is a SHA-256 of the two native libraries.
- Only the archive is checked, not what the process loads at runtime.

## License

PolyForm Small Business 1.0.0.

Required Notice: Copyright 2026 sonekkdev (https://github.com/sonekkdev/sonekk-seal3)
