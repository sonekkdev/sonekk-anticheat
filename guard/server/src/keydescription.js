import { children, parse, bytes, readTLV, toInt } from './der.js'

// Android Key Attestation extension: 1.3.6.1.4.1.11129.2.1.17
const OID = Buffer.from('2b06010401d679020111', 'hex')

const VERIFIED_BOOT_STATE = { 0: 'verified', 1: 'self_signed', 2: 'unverified', 3: 'failed' }

/**
 * Pulls the attestation extension out of a certificate.
 * @param {Buffer} der raw certificate bytes
 * @returns {Buffer|null} the extnValue content, which is a KeyDescription SEQUENCE
 */
export function findExtensionValue (der) {
  try {
    const certificate = parse(der)
    const tbs = children(der, certificate)[0]
    if (!tbs) return null

    const candidates = children(der, tbs)
    const container = candidates.find((node) => node.cls === 2 && node.tag === 3 && node.constructed)
    if (!container) return null

    const list = children(der, container)[0]
    if (!list) return null

    for (const extension of children(der, list)) {
      const parts = children(der, extension)
      if (parts.length < 2) continue
      if (!bytes(der, parts[0]).equals(OID)) continue
      const value = parts[parts.length - 1]
      if (value.cls !== 0 || value.tag !== 4) return null
      return Buffer.from(bytes(der, value))
    }
    return null
  } catch {
    return null
  }
}

/**
 * KeyDescription ::= SEQUENCE {
 *   attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
 *   keymasterVersion INTEGER, keymasterSecurityLevel ENUMERATED,
 *   attestationChallenge OCTET STRING, uniqueId OCTET STRING,
 *   softwareEnforced AuthorizationList, teeEnforced AuthorizationList }
 *
 * Only the fields that matter for a cheat decision are surfaced.
 */
export function parseKeyDescription (der) {
  const root = readTLV(der, 0)
  if (root.cls !== 0 || root.tag !== 0x10) throw new Error('not a sequence')
  const fields = children(der, root)
  if (fields.length < 8) throw new Error('short key description')

  const result = {
    attestationVersion: toInt(der, fields[0]),
    attestationSecurityLevel: toInt(der, fields[1]),
    keymasterVersion: toInt(der, fields[2]),
    keymasterSecurityLevel: toInt(der, fields[3]),
    challenge: bytes(der, fields[4]).toString('utf8'),
    verifiedBootState: null,
    deviceLocked: null,
    verifiedBootHash: null
  }

  const teeEnforced = fields[fields.length - 1]
  for (const item of children(der, teeEnforced)) {
    if (item.cls !== 2) continue
    const inner = children(der, item)[0]
    if (!inner) continue

    if (item.tag === 503) result.verifiedBootState = toInt(der, inner)
    if (item.tag === 704) result.deviceLocked = bytes(der, inner)[0] !== 0
    if (item.tag === 705) result.verifiedBootHash = Buffer.from(bytes(der, inner)).toString('hex')
  }

  result.bootStateName = result.verifiedBootState === null
    ? 'unknown'
    : VERIFIED_BOOT_STATE[result.verifiedBootState] ?? 'unknown'
  return result
}

export function inspectCertificate (cert) {
  const extension = findExtensionValue(cert.raw)
  if (!extension) return null
  try {
    return parseKeyDescription(extension)
  } catch {
    return null
  }
}
