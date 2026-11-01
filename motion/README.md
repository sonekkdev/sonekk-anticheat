# Sonekk Motion

Server side movement validation for physically driven VR games, Gorilla Tag fangames included. The companion to [Sonekk Guard](https://github.com/sonekkdev/sonekk-guard): Guard checks the device, Motion checks the gameplay.

The client sends position samples, the server decides whether the movement was physically possible. Nothing here can be patched out of an APK.

## Detections

| Rule | What it catches |
|---|---|
| `speed` | horizontal speed above the limit for several consecutive samples |
| `fly` | sustained airborne movement without a legal impulse |
| `teleport` | displacement larger than the speed limit allows in one sample |
| `accel` | impossible vertical impulse |
| `ground` | claims to be standing metres above the floor |

## Enforcement ladder

One event is one strike.

1. kick with the reason
2. kick with a warning
3. ban

Strikes decay after seven days, and a three second grace window after joining means lag and spawns never punish an innocent player. Samples flagged `respawn`, `teleport` or `knockback` are ignored, including the one right after.

## Endpoint

```
POST /v1/movement
{ "playerId": "abc", "joinedAt": 1690000000000, "samples": [
  { "t": 0, "x": 0, "y": 1, "z": 0, "grounded": true, "groundY": 0 }
] }
```

Response: `{ "action": "allow" | "kick" | "ban", "strikes": 1, "reason": "fly" }`.

```js
import { createMovementHandler, StrikeStore } from './src/movement.js'
const handle = createMovementHandler({ onAction: ({ action, playerId }) => disconnect(playerId) })
```

## Unity side

`unity/Runtime/MovementReporter.cs` samples the player at 10 Hz, posts batches, and raises `OnAction("kick" | "ban")` so your game disconnects. Call `MarkLegalMove()` after a respawn or an intentional teleport.

## Tuning

Defaults assume a Gorilla Tag style game: 6.5 m/s horizontal, 22 m/s^2 acceleration, 8 airborne samples to flag flight. Every game differs, so run a session with your best players and set the limits above their real peaks.

## Limits

- Needs a trustworthy `grounded` signal from the game. If the client reports it dishonestly, combined with Guard it is still a signal, alone it is not.
- No wall or geometry checks yet.
- Strike state is in memory. Restart the process and recent strikes are gone, so swap in your own store for production.
- It validates physics, not intent. A very good player is still a very good player.

## License

PolyForm Small Business 1.0.0.

Required Notice: Copyright 2026 sonekkdev (https://github.com/sonekkdev/sonekk-motion)
