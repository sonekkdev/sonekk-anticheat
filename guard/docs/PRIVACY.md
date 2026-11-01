# Privacy

Sonekk Guard is built to collect as little as possible, because anti-cheat telemetry is personal data in most jurisdictions.

## What is collected

Only process local state, evaluated on the device:

- `/proc/self/maps`, `/proc/self/status`, `/proc/self/mounts`
- Existence of known root and hook artefact paths
- A short list of `ro.*` build properties
- Whether Frida's default port is listening
- The SHA-256 of your own native library
- Whether the APK signature matches the one you pinned

## What is not collected

- Advertising id, IMEI, serial, Android id, MAC address, IP address
- Installed apps, contacts, files outside the app sandbox
- Message contents, voice, camera or tracking data
- Any persistent device fingerprint

Reports contain finding ids, weights and short technical details. That is all.

## Player identifiers

The library never sends one. If your game wants to attribute a report, `GuardRunner.playerId` appends your own player id to the payload. That is your data and your policy.

## Retention

The reference server keeps nothing: it logs a one line verdict and returns. If you store reports, keep them no longer than you need them for moderation, and document that in your own privacy policy.

## Store disclosure

Meta and Pico both require you to disclose anti-cheat and integrity collection in your privacy policy and store listing. Say plainly: "we check whether the device has been modified, to detect cheating".

## GDPR note

Finding ids and timestamps tied to a player id are personal data. Decide a legal basis before you store them, and honour deletion requests.
