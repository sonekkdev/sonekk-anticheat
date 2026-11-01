import { randomBytes } from 'node:crypto'

/**
 * One shot nonces. A report is only accepted with a nonce the server issued and has
 * not seen before, which makes replaying a captured report useless.
 */
export class ChallengeStore {
  constructor ({ ttlMs = 120_000, max = 10_000 } = {}) {
    this.ttlMs = ttlMs
    this.max = max
    this.entries = new Map()
  }

  issue () {
    this.sweep()
    if (this.entries.size >= this.max) {
      // Refuse to grow without bound rather than evicting live challenges.
      return null
    }
    const nonce = randomBytes(16).toString('hex')
    this.entries.set(nonce, Date.now() + this.ttlMs)
    return nonce
  }

  /** Registers a caller supplied nonce. Used by tests and by migration paths. */
  remember (nonce, ttlMs = this.ttlMs) {
    if (typeof nonce !== 'string' || nonce.length !== 32) return false
    this.entries.set(nonce, Date.now() + ttlMs)
    return true
  }

  /** Returns true exactly once for a valid, unexpired nonce. */
  consume (nonce) {
    if (typeof nonce !== 'string' || nonce.length !== 32) return false
    const expiry = this.entries.get(nonce)
    if (expiry === undefined) return false
    this.entries.delete(nonce)
    return Date.now() <= expiry
  }

  sweep () {
    const now = Date.now()
    for (const [nonce, expiry] of this.entries) {
      if (expiry < now) this.entries.delete(nonce)
    }
  }

  get size () {
    return this.entries.size
  }
}
