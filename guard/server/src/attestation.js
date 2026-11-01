import { X509Certificate, createVerify } from 'node:crypto'

/**
 * Android Key Attestation chain checks.
 *
 * What this proves: the certificate chain is signed up to a root you pinned, the
 * certificates are currently valid, and the leaf key signed the server challenge.
 * That is genuine hardware backed evidence, because only the TEE holds the leaf key.
 *
 * What this does not do yet: parse the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
 * to read verifiedBootState, deviceLocked and the package name hash. That needs an
 * ASN.1 reader. Until then, treat a valid chain as "key lives in a TEE", not as
 * "bootloader is locked".
 */

/** @param {string[]} base64Certs leaf first, root last */
export function parseChain (base64Certs) {
  if (!Array.isArray(base64Certs) || base64Certs.length === 0) return []
  const out = []
  for (const entry of base64Certs.slice(0, 8)) {
    if (typeof entry !== 'string' || entry.length === 0) return []
    try {
      out.push(new X509Certificate(Buffer.from(entry, 'base64')))
    } catch {
      return []
    }
  }
  return out
}

/**
 * @param {{ chain: X509Certificate[], roots: X509Certificate[], now?: number }} input
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyChain ({ chain, roots, now = Date.now() }) {
  if (!chain || chain.length === 0) return { ok: false, reason: 'empty_chain' }
  if (!roots || roots.length === 0) return { ok: false, reason: 'no_trusted_roots' }

  for (const cert of chain) {
    const from = Date.parse(cert.validFrom)
    const to = Date.parse(cert.validTo)
    if (!Number.isFinite(from) || !Number.isFinite(to)) return { ok: false, reason: 'bad_dates' }
    if (now < from) return { ok: false, reason: 'cert_not_yet_valid' }
    if (now > to) return { ok: false, reason: 'cert_expired' }
  }

  for (let i = 0; i < chain.length - 1; i += 1) {
    if (!chain[i].checkIssued(chain[i + 1])) return { ok: false, reason: 'broken_link' }
    let valid = false
    try {
      valid = chain[i].verify(chain[i + 1].publicKey)
    } catch {
      valid = false
    }
    if (!valid) return { ok: false, reason: 'bad_signature' }
  }

  const anchor = chain[chain.length - 1]
  const trusted = roots.some((root) => root.fingerprint256 === anchor.fingerprint256)
  if (!trusted) return { ok: false, reason: 'untrusted_root' }

  return { ok: true }
}

/** Proof of possession: the leaf key must sign the challenge the server issued. */
export function verifyProofOfPossession ({ leaf, challenge, signature }) {
  if (!leaf || typeof challenge !== 'string' || typeof signature !== 'string') return false
  try {
    const verifier = createVerify('sha256')
    verifier.update(challenge, 'utf8')
    verifier.end()
    return verifier.verify(leaf.publicKey, Buffer.from(signature, 'base64'))
  } catch {
    return false
  }
}

/** @param {string[]} pems */
export function rootsFromPem (pems) {
  const roots = []
  for (const pem of pems) {
    const matches = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []
    for (const block of matches) {
      try {
        roots.push(new X509Certificate(block))
      } catch {
        // Ignore malformed anchors rather than trusting them.
      }
    }
  }
  return roots
}
