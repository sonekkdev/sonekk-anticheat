// Minimal DER reader. Only what certificate and attestation parsing needs.

export function readTLV (buf, offset) {
  if (offset + 2 > buf.length) throw new Error('truncated')
  const first = buf[offset]
  const cls = first >> 6
  const constructed = (first & 0x20) !== 0
  let tag = first & 0x1f
  let cursor = offset + 1

  if (tag === 0x1f) {
    tag = 0
    for (let i = 0; i < 4; i += 1) {
      if (cursor >= buf.length) throw new Error('truncated tag')
      const byte = buf[cursor]
      cursor += 1
      tag = (tag << 7) | (byte & 0x7f)
      if ((byte & 0x80) === 0) break
    }
  }

  if (cursor >= buf.length) throw new Error('truncated length')
  let length = buf[cursor]
  cursor += 1
  if (length & 0x80) {
    const bytes = length & 0x7f
    if (bytes === 0 || bytes > 4) throw new Error('bad length')
    length = 0
    for (let i = 0; i < bytes; i += 1) {
      if (cursor >= buf.length) throw new Error('truncated length')
      length = (length << 8) | buf[cursor]
      cursor += 1
    }
  }

  if (cursor + length > buf.length) throw new Error('truncated value')
  return { cls, constructed, tag, valueStart: cursor, valueEnd: cursor + length, end: cursor + length }
}

export function children (buf, node) {
  const out = []
  let cursor = node.valueStart
  while (cursor < node.valueEnd) {
    const child = readTLV(buf, cursor)
    out.push(child)
    cursor = child.end
  }
  return out
}

export function bytes (buf, node) {
  return buf.subarray(node.valueStart, node.valueEnd)
}

export function toInt (buf, node) {
  let value = 0
  for (const byte of bytes(buf, node)) value = (value << 8) | byte
  return value
}

export function parse (der) {
  return readTLV(der, 0)
}
