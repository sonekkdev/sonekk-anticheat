# Sonekk Anti-Cheat

Four layers, one repository. They are independent on purpose: each answers a different question, and you deploy only the ones your game needs.

| Layer | Question it answers | Where it runs |
|---|---|---|
| [guard](guard) | Is the device clean? root, Frida, hooks, runtime patches | client native library + your server |
| [motion](motion) | Is this movement physically possible? speed, flight, teleports | your server |
| [seal](seal) | Is this the build I shipped? repacks, injected libraries | build time + your server |
| [antiadb](antiadb) | Did ADB touch the session? settings changed mid match | your game + your server |

Together they cover the whole chain a Gorilla Tag style fan game actually gets attacked through: a repacked APK, a modded runtime, a movement hack, and a player poking the device with ADB while connected.

## Why four and not one

Because the trust model differs:

- **guard** runs inside the app and can be patched, so its verdict is only a signal.
- **motion** reads what the game reports, so it cannot be patched out, but it can only see physics.
- **seal** runs offline on the APK, so it cannot lie to itself, but it cannot see runtime state.
- **antiadb** watches effects of external commands, so it is the only one that sees a player fiddling with the headset mid match.

Merging them into one binary would make one bypass defeat all four.

## Quick start

```bash
# Node layers
node --test motion/test/movement.test.js
node --test seal/test/seal.test.js
node --test antiadb/test/watch.test.js
node --test guard/server/test/guard.test.js

# Native layer
cmake -S guard/native -B guard/native/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build guard/native/build
ctest --test-dir guard/native/build --output-on-failure
```

## Enforcement, shared across the layers

Kick first, ban later, never on the first event:

1. first event: kick with the reason
2. second event: kick with a warning
3. third event: ban

Strikes decay after seven days, and developer mode alone is never a ban: antiadb only warns, and only acts when a watched value changes mid session.

## License

PolyForm Small Business 1.0.0, free for companies under 100 people and under 1M USD revenue.

Required Notice: Copyright 2026 sonekkdev (https://github.com/sonekkdev/sonekk-anticheat)
