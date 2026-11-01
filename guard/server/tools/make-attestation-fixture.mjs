// Builds the DER blob for an Android KeyDescription extension, used to create a
// realistic certificate fixture. Run: node tools/make-attestation-fixture.mjs
//
// KeyDescription ::= SEQUENCE {
//   attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
//   keymasterVersion INTEGER, keymasterSecurityLevel ENUMERATED,
//   attestationChallenge OCTET STRING, uniqueId OCTET STRING,
//   softwareEnforced AuthorizationList, teeEnforced AuthorizationList }

const OID_KEY_ATTESTATION = Buffer.from('2b06010401d679020111', 'hex')

function tlv (tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.concat(content)
  const length = body.length
  let header
  if (length < 0x80) {
    header = Buffer.from([tag, length])
  } else if (length < 0x100) {
    header = Buffer.from([tag, 0x81, length])
  } else {
    header = Buffer.from([tag, 0x82, length >> 8, length & 0xff])
  }
  return Buffer.concat([header, body])
}

function uintToBytes (value) {
  const out = []
  let v = value
  do {
    out.unshift(v & 0xff)
    v = Math.floor(v / 128)
  } while (v > 0)
  return Buffer.from(out)
}

const integer = (value) => tlv(0x02, uintToBytes(value))
const enumerated = (value) => tlv(0x0a, uintToBytes(value))
const boolean = (value) => tlv(0x01, Buffer.from([value ? 0xff : 0x00]))
const octets = (buf) => tlv(0x04, buf)
const sequence = (items) => tlv(0x30, items)

// Context specific, constructed, explicit tagging. High tag numbers use base 128
// with the continuation bit set on every byte but the last.
const tagBytes = (tag) => {
  const out = [tag & 0x7f]
  let value = Math.floor(tag / 128)
  while (value > 0) {
    out.unshift((value & 0x7f) | 0x80)
    value = Math.floor(value / 128)
  }
  return Buffer.from(out)
}

const explicit = (tag, inner) => {
  const first = Buffer.concat([Buffer.from([0xbf]), tagBytes(tag)])
  const body = Buffer.concat([inner])
  if (body.length < 0x80) return Buffer.concat([first, Buffer.from([body.length]), body])
  if (body.length < 0x100) return Buffer.concat([first, Buffer.from([0x81, body.length]), body])
  return Buffer.concat([first, Buffer.from([0x82, body.length >> 8, body.length & 0xff]), body])
}

export function buildKeyDescription ({ challenge, verifiedBootState = 0, deviceLocked = true }) {
  const teeEnforced = sequence([
    explicit(503, enumerated(verifiedBootState)),
    explicit(704, boolean(deviceLocked)),
    explicit(705, octets(Buffer.alloc(32, 0x11)))
  ])

  return sequence([
    integer(3),
    enumerated(1),
    integer(4),
    enumerated(1),
    octets(Buffer.from(challenge, 'utf8')),
    octets(Buffer.alloc(0)),
    sequence([]),
    teeEnforced
  ])
}

export { OID_KEY_ATTESTATION }

const arg = (name, fallback) => {
  const index = process.argv.indexOf('--' + name)
  return index === -1 ? fallback : process.argv[index + 1]
}

if (process.argv[1]?.endsWith('make-attestation-fixture.mjs')) {
  const extension = buildKeyDescription({
    challenge: arg('challenge', '0123456789abcdef0123456789abcdef'),
    verifiedBootState: Number(arg('state', '0')),
    deviceLocked: arg('locked', 'true') !== 'false'
  })
  console.log(extension.toString('hex'))
}
