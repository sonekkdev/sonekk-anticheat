/**
 * Fixed window rate limiter. Enough to blunt scripted abuse; put real limiting in
 * front of this if you expose the endpoint to the internet.
 */
export class RateLimiter {
  constructor ({ limit = 60, windowMs = 60_000 } = {}) {
    this.limit = limit
    this.windowMs = windowMs
    this.buckets = new Map()
  }

  allow (key) {
    const now = Date.now()
    const bucket = this.buckets.get(key)
    if (!bucket || now >= bucket.resetAt) {
      this.buckets.set(key, { count: 1, resetAt: now + this.windowMs })
      if (this.buckets.size > 10_000) this.prune(now)
      return true
    }
    if (bucket.count >= this.limit) return false
    bucket.count += 1
    return true
  }

  prune (now = Date.now()) {
    for (const [key, bucket] of this.buckets) {
      if (now >= bucket.resetAt) this.buckets.delete(key)
    }
  }
}
