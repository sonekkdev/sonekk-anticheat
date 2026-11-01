import { readFileSync } from 'node:fs'

const EOCD = 0x06054b50
const CENTRAL = 0x02014b50

/** Minimal ZIP central directory reader, enough for APK integrity work. */
export function readEntries (buffer) {
  let eocd = -1
  for (let i = buffer.length - 22; i >= 0; i -= 1) {
    if (buffer.readUInt32LE(i) === EOCD) {
      eocd = i
      break
    }
  }
  if (eocd === -1) throw new Error('not a zip file, no end of central directory')

  const count = buffer.readUInt16LE(eocd + 10)
  let offset = buffer.readUInt32LE(eocd + 16)
  const entries = []

  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(offset) !== CENTRAL) throw new Error('corrupt central directory')
    const crc = buffer.readUInt32LE(offset + 16)
    const compressedSize = buffer.readUInt32LE(offset + 20)
    const uncompressedSize = buffer.readUInt32LE(offset + 24)
    const nameLength = buffer.readUInt16LE(offset + 28)
    const extraLength = buffer.readUInt16LE(offset + 30)
    const commentLength = buffer.readUInt16LE(offset + 32)
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString('utf8')
    entries.push({ name, crc, size: uncompressedSize, compressedSize })
    offset += 46 + nameLength + extraLength + commentLength
  }

  return entries
}

export function readApk (path) {
  return readEntries(readFileSync(path))
}
