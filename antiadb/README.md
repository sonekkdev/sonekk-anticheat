# Sonekk AntiADB 4

Detects ADB activity during a VR session without banning people for having developer mode on.

An Android app cannot see the adb process, so this watches the effects adb commands leave behind: a refresh rate changed by `set refresh rate 90`, properties flipped, wireless adb appearing on port 5555.

## Behaviour

| Situation | Result |
|---|---|
| quiet session | allow |
| developer mode on, nothing happened | one time notice, asking the player to turn ADB off while playing |
| any watched value changed mid session | kick, with the exact change as the reason |
| developer mode on and a change happened | kick, plus the notice |

It never bans. Kicks are reported to your server so repeat behaviour is visible, and the decision about what happens next stays with your game and Sonekk Motion 2.

## Usage

```js
import { assess, WATCHED } from './src/watch.js'

const before = snapshot()          // taken when the match starts
// ...20 seconds later
const result = assess(before, snapshot())
if (result.action === 'kick') disconnect(playerId, result.reasons.join(', '))
if (result.action === 'notice') ui.ShowBanner(result.notice)
```

`snapshot()` is yours to implement: read `Settings.Global` for `adb_enabled` and `adb_wifi_enabled`, `XRSettings.refreshRate`, `stay_on_while_plugged_in`, USB attached state, and check `/proc/net/tcp` for a listener on 5555.

## What this cannot do

- Headlock and friends are not adb commands, they load code. Use Sonekk Guard 1 for module integrity and Sonekk Seal 3 for repacked APKs.
- A cheater who turns ADB off for the match is invisible here.
- Reading another process's adb commands needs root, which is exactly what Guard 1 screens for.

## License

PolyForm Small Business 1.0.0.

Required Notice: Copyright 2026 sonekkdev (https://github.com/sonekkdev/sonekk-antiadb4)
