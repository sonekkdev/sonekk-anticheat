import { parseChain, verifyChain, verifyProofOfPossession } from './attestation.js'
import { ChallengeStore } from './challenge.js'
import { inspectCertificate } from './keydescription.js'
import { RateLimiter } from './ratelimit.js'
import { decide, scoreReport } from './scoring.js'
import { verifySignature } from './verify.js'

const MAX_BODY = 16 * 1024

/**
 * Reference endpoint. No framework, no storage, no outbound calls.
 *
 * Flow:
 *   1. Client POSTs /v1/challenge, gets a single use nonce.
 *   2. Client collects findings, builds the report with the nonce, signs it with HMAC.
 *   3. Server consumes the nonce, checks the HMAC, optionally verifies the attestation
 *      chain and proof of possession, then scores the findings itself.
 *
 * @param {{
 *   secret?: string,
 *   challenges?: ChallengeStore,
 *   limiter?: RateLimiter,
 *   roots?: import('node:crypto').X509Certificate[],
 *   requireChallenge?: boolean,
 *   requireAttestation?: boolean,
 *   onReport?: (report: object) => void,
 *   now?: () => number
 * }} options
 */
export function createApp (options = {}) {
  const secret = options.secret ?? ''
  const challenges = options.challenges ?? new ChallengeStore()
  const limiter = options.limiter ?? new RateLimiter({ limit: 120, windowMs: 60_000 })
  const roots = options.roots ?? []
  const requireChallenge = options.requireChallenge ?? true
  const requireAttestation = options.requireAttestation ?? false
  const onReport = options.onReport ?? (() => {})
  const now = options.now ?? (() => Date.now())

  return async function handle (req, res) {
    const ip = req.socket?.remoteAddress ?? 'unknown'
    if (!limiter.allow(ip)) return send(res, 429, { error: 'rate_limited' })

    const path = (req.url ?? '').split('?')[0]

    if (path === '/healthz') return send(res, 200, { ok: true })

    if (path === '/v1/challenge') {
      if (req.method !== 'POST' && req.method !== 'GET') return send(res, 405, { error: 'method_not_allowed' })
      const nonce = challenges.issue()
      if (!nonce) return send(res, 503, { error: 'challenge_store_full' })
      return send(res, 200, { nonce, expiresInMs: challenges.ttlMs })
    }

    if (path === '/v1/report') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' })

      let rawBody
      try {
        rawBody = await readBody(req)
      } catch (error) {
        return send(res, error.code === 'TOO_LARGE' ? 413 : 400, { error: 'bad_body' })
      }

      if (secret && !verifySignature(rawBody, req.headers['x-sonekk-signature'], secret)) {
        return send(res, 401, { error: 'bad_signature' })
      }

      let payload
      try {
        payload = JSON.parse(rawBody.toString('utf8'))
      } catch {
        return send(res, 400, { error: 'bad_json' })
      }

      if (!payload || payload.v !== 1 || !Array.isArray(payload.findings)) {
        return send(res, 400, { error: 'bad_report' })
      }

      if (requireChallenge) {
        if (!challenges.consume(payload.nonce)) {
          return send(res, 401, { error: 'bad_challenge' })
        }
      }

      let attested = false
      let trusted = false
      let bootState = null
      if (payload.attestation && roots.length > 0 && typeof payload.nonce === 'string') {
        const chain = parseChain(payload.attestation.chain)
        const chainResult = verifyChain({ chain, roots, now: now() })
        const proof = chainResult.ok
          ? verifyProofOfPossession({
              leaf: chain[0],
              challenge: payload.nonce,
              signature: payload.attestation.signature
            })
          : false
        const keyDescription = chainResult.ok && proof ? inspectCertificate(chain[0]) : null

        // The challenge inside the signed extension is the binding that matters:
        // an attacker cannot reuse an attestation from another session.
        attested = Boolean(
          chainResult.ok && proof && keyDescription && keyDescription.challenge === payload.nonce
        )
        bootState = keyDescription ? keyDescription.bootStateName : null
        trusted = attested && bootState === 'verified' && keyDescription.deviceLocked === true
      }

      if (requireAttestation && !trusted) {
        return send(res, 401, { error: 'attestation_required' })
      }

      // Client supplied score and verdict are ignored, always.
      const { score, findings } = scoreReport(payload.findings)
      const verdict = decide(score)

      onReport({
        playerId: typeof payload.player === 'string' ? payload.player.slice(0, 128) : null,
        score,
        verdict,
        attested,
        trusted,
        bootState,
        findings,
        sdk: typeof payload.sdk === 'string' ? payload.sdk.slice(0, 32) : 'unknown',
        receivedAt: new Date(now()).toISOString()
      })

      return send(res, 200, { verdict, score, attested, trusted, bootState })
    }

    return send(res, 404, { error: 'not_found' })
  }
}

async function readBody (req) {
  let size = 0
  const chunks = []
  for await (const chunk of req) {
    size += chunk.length
    if (size > MAX_BODY) {
      const error = new Error('too large')
      error.code = 'TOO_LARGE'
      req.destroy()
      throw error
    }
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
}

function send (res, status, body) {
  const json = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(json),
    'cache-control': 'no-store'
  })
  res.end(json)
}
