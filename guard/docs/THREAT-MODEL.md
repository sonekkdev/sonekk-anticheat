# Threat model

## Who you are defending against

**Script kid.** Downloads a Frida script or a repacked APK. Runs it, gets aim assist, gets bored. This is 90 percent of the problem and every check here stops them.

**Modder.** Has root, uses Magisk with Zygisk and a hiding module, knows how to kill a detection thread. They read this source, find the collector, and patch the return value. Expect a bypass within days of each release.

**Determined attacker.** Custom kernel, spoofed keystore keybox, patched client that reports nothing. No on-device check survives this. Your only real defences are server authority and account level response.

## What this library can honestly do

- Stop the mass market. That is worth a lot, because the mass market is what ruins a small VR game's lobbies.
- Raise the cost of the next tier from minutes to hours.
- Produce evidence you can act on with review, not automatic bans.

## What it cannot do

- Prove to your server that the client is honest. Any signal can be forged once the library is patched.
- Detect a cheat that never touches your process, such as a driver level input injector on a rooted headset.
- Survive a custom kernel that hides mounts and processes from `/proc`.

The signature on reports stops trivial `curl` spam, nothing more. Treat the secret as public.

## Signals that survive a patched client

1. **Reporting gaps.** A player with 40 hours and zero reports is anomalous.
2. **Attestation.** Once Keystore attestation is wired up, a client that cannot produce a valid chain is a signal even if every other check is silent.
3. **Behaviour.** Aim curves, reaction time distributions, head to hand correlation. Expensive to fake, invisible to the attacker until you act.
4. **Server authority.** If the client cannot decide whether a shot landed, cheating becomes visual only.

## Response policy

Never auto ban on score alone. Suggested ladder:

| Score | Action |
| --- | --- |
| 0 to 19 | nothing |
| 20 to 49 | log, keep history |
| 50 to 99 | shadow lobby, manual review |
| 100+ | review queue with priority, not an automatic ban |

False positives matter more than cheaters on a small playerbase. Root is common among VR developers, modders and emulator users. A developer build with `ro.debuggable=1` is not a cheater.

## How it will be broken

These are the three vectors any intermediate reverse engineer will try. Two of them now have a countermeasure in the code, one is structural.

**1. Pull the HMAC key out of the APK and forge clean reports.**
The key has to live in the client, so `Il2CppDumper` plus a memory dump gets it in minutes. With the key and a fresh nonce you can detach the native library entirely and post a perfect report. The HMAC is a spam filter, not authentication.
Real mitigation: attestation. A TEE key cannot be exported, so a signature over the nonce from a verified chain is the only proof that cannot be fabricated on a rooted device. Server support is implemented and tested, the client request is not.

**2. Hook `openat` or `read` before the library loads and rewrite `/proc/self/maps`.**
Zygisk, Magisk and KernelSU modules do this comfortably, and a patched `UnityPlayerActivity` can install the hook before the first game instruction.
Implemented countermeasures: reads go through raw `syscall()` instead of libc wrappers, and the module list from `dl_iterate_phdr` is cross checked against the maps text. A library that is loaded but missing from maps is `instrumentation.inconsistent` (70). That catches naive hooks that sanitise one view and forget the other.
Not defeated: a kernel level hook that lies consistently in both views.

**3. Patch the code in memory after load, leaving the `.so` on disk pristine.**
A file hash proves nothing about the running image.
Implemented countermeasure: `integrity.memory_text` hashes the executable `PT_LOAD` segments that are actually mapped and compares them against the same byte ranges read from the file. Anything patched after load fails the comparison. If the bytes cannot be read, the check is skipped rather than guessed.
Remaining gap: a patch applied in the window between our read and the comparison, and a kernel that lies about our own mappings.

**4. Strip the library.**
The client can simply not load `libsonekk_guard.so`. That produces no findings, which is why reporting gaps matter: a player with 40 hours and zero reports is the anomaly. Do not treat silence as innocence.

## Known gaps

- Client attestation is written but unverified: it has never run on a device or been compiled in Unity
- The HMAC key is extractable from the APK by design, it is not an authentication mechanism
- `integrity.memory_text` cannot see a patch applied between the memory read and the comparison
- A kernel level hook that lies consistently defeats every userland check here
- The attestation extension parser is tested against synthetic DER, not a chain from real hardware
- No behavioural checks, they belong in your game server
- Weights are unvalidated guesses
- Rate limiting is per IP and in memory, it does not survive a restart or a load balancer
