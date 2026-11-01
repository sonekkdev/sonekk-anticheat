// Server side movement validation for physically driven VR games such as Gorilla Tag
// fangames. The client sends samples, the server decides, and nothing here can be
// patched out of an APK.

export const DEFAULTS = {
  maxSpeed: 6.5,        // m/s horizontal
  maxVertical: 7.0,     // m/s upwards
  maxAccel: 22,         // m/s^2
  teleportAllowance: 1.5,
  speedSamples: 5,
  flySamples: 8,
  groundTolerance: 1.6,
  graceMs: 3000,
  decayMs: 7 * 24 * 60 * 60 * 1000,
  kickAt: 1,
  banAt: 3,
  maxSamples: 400
}

const horizontal = (a, b) => Math.hypot(b.x - a.x, b.z - a.z)
const vertical = (a, b) => Math.abs(b.y - a.y)
const deltaSeconds = (a, b) => Math.max(0.001, (b.t - a.t) / 1000)

/**
 * @param {{t:number,x:number,y:number,z:number,grounded?:boolean,groundY?:number,flags?:string[]}[]} samples
 * @param {Partial<typeof DEFAULTS>} options
 * @returns {{type:string,detail:string,at:number}[]}
 */
export function analyseSamples (samples, options = {}) {
  const config = { ...DEFAULTS, ...options }
  const list = (samples ?? []).slice(0, config.maxSamples)
  const violations = []
  if (list.length < 3) return violations

  let fastRun = 0
  let airborne = 0
  let peakSpeed = 0
  let flyFrom = null
  let skipNext = false

  for (let i = 1; i < list.length; i += 1) {
    const previous = list[i - 1]
    const current = list[i]
    const flags = new Set(current.flags ?? [])
    if (flags.has('respawn') || flags.has('teleport') || flags.has('knockback')) {
      fastRun = 0
      airborne = 0
      flyFrom = null
      skipNext = true
      continue
    }

    // The sample after a legal teleport or respawn also has a big delta, ignore it.
    if (skipNext) {
      skipNext = false
      fastRun = 0
      airborne = 0
      continue
    }

    const dt = deltaSeconds(previous, current)
    const speed = horizontal(previous, current) / dt
    const rise = vertical(previous, current) / dt
    const jump = Math.hypot(current.x - previous.x, current.y - previous.y, current.z - previous.z)

    // Teleport: displacement far beyond what any legal speed allows in one sample.
    if (jump > config.maxSpeed * dt * 3 + config.teleportAllowance) {
      violations.push({
        type: 'teleport',
        detail: `${jump.toFixed(1)} m in ${(dt * 1000).toFixed(0)} ms`,
        at: current.t
      })
    }

    if (speed > config.maxSpeed) {
      fastRun += 1
      peakSpeed = Math.max(peakSpeed, speed)
      if (fastRun >= config.speedSamples) {
        violations.push({
          type: 'speed',
          detail: `${speed.toFixed(1)} m/s sustained, limit ${config.maxSpeed}`,
          at: current.t
        })
        fastRun = 0
      }
    } else {
      fastRun = 0
    }

    if (rise > config.maxAccel) {
      violations.push({ type: 'accel', detail: `vertical impulse ${rise.toFixed(1)} m/s`, at: current.t })
    }

    const grounded = current.grounded !== false
    if (current.grounded === false) {
      airborne += 1
      if (flyFrom === null) flyFrom = i
      if (airborne >= config.flySamples && rise > -0.5) {
        violations.push({
          type: 'fly',
          detail: `${airborne} samples airborne while not falling`,
          at: current.t
        })
        airborne = 0
      }
    } else {
      airborne = 0
      flyFrom = null
    }

    if (grounded && typeof current.groundY === 'number') {
      const height = current.y - current.groundY
      if (height > config.groundTolerance) {
        violations.push({
          type: 'ground',
          detail: `claims grounded ${height.toFixed(1)} m above the floor`,
          at: current.t
        })
      }
    }
  }

  return violations
}

/**
 * Strike ladder: one event is one strike, kicks escalate, the third ends in a ban.
 * Strikes decay so a bad afternoon is not a permanent record.
 */
export class StrikeStore {
  constructor (options = {}) {
    this.config = { ...DEFAULTS, ...options }
    this.players = new Map()
  }

  record (playerId, violations, now = Date.now()) {
    const entry = this.get(playerId, now)
    entry.strikes += 1
    entry.lastReason = violations.map((violation) => violation.type).join(', ')
    entry.lastAt = now

    let action = 'allow'
    if (entry.strikes >= this.config.banAt) action = 'ban'
    else if (entry.strikes >= this.config.kickAt) action = 'kick'

    return { action, strikes: entry.strikes, reason: entry.lastReason }
  }

  get (playerId, now = Date.now()) {
    let entry = this.players.get(playerId)
    if (!entry || now - entry.lastAt > this.config.decayMs) {
      entry = { strikes: 0, lastAt: now, lastReason: '' }
      this.players.set(playerId, entry)
    }
    return entry
  }

  strikes (playerId, now = Date.now()) {
    return this.get(playerId, now).strikes
  }
}

/**
 * HTTP handler. Expects { playerId, joinedAt?, samples: [...] } and answers with the
 * action the game should take. No storage beyond the in memory strike table.
 */
export function createMovementHandler (options = {}) {
  const config = { ...DEFAULTS, ...options }
  const store = options.store ?? new StrikeStore(config)
  const onAction = options.onAction ?? (() => {})
  const now = options.now ?? (() => Date.now())

  return async function handleMovement (req, res) {
    if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' })

    let size = 0
    const chunks = []
    for await (const chunk of req) {
      size += chunk.length
      if (size > 256 * 1024) {
        req.destroy()
        return send(res, 413, { error: 'payload_too_large' })
      }
      chunks.push(chunk)
    }

    let payload
    try {
      payload = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    } catch {
      return send(res, 400, { error: 'bad_json' })
    }

    if (!payload || typeof payload.playerId !== 'string' || !Array.isArray(payload.samples)) {
      return send(res, 400, { error: 'bad_payload' })
    }

    const timestamp = now()
    if (typeof payload.joinedAt === 'number' && timestamp - payload.joinedAt < config.graceMs) {
      return send(res, 200, { action: 'allow', strikes: store.strikes(payload.playerId, timestamp), reason: 'grace' })
    }

    const violations = analyseSamples(payload.samples, config)
    if (violations.length === 0) {
      return send(res, 200, { action: 'allow', strikes: store.strikes(payload.playerId, timestamp), reason: '' })
    }

    const result = store.record(payload.playerId, violations, timestamp)
    onAction({ playerId: payload.playerId, ...result, violations })
    return send(res, 200, result)
  }
}

function send (res, status, body) {
  const json = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(json) })
  res.end(json)
}
