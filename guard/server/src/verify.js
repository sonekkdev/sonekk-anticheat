import { createHmac, timingSafeEqual } from 'node:crypto'

/**
 * HMAC over the exact bytes received. This only stops casual spam: a determined
 * attacker has the secret inside the APK. Never treat it as a trust boundary.
 *
 * @param {Buffer|string} rawBody
 * @param {string} signature hex digest from the X-Sonekk-Signature header
 * @param {string} secret
 */
export function verifySignature (rawBody, signature, secret) {
  if (!signature || !secret) return false
  const expected = createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(rawBody)
    .digest('hex')

  const provided = String(signature).trim().toLowerCase()
  if (provided.length !== expected.length) return false

  try {
    return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(provided, 'hex'))
  } catch {
    return false
  }
}
