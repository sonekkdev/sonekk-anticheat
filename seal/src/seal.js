import { readApk } from './zip.js'

const MOD_PATTERNS = [
  /libmodmenu/i,
  /libmelon/i,
  /libbepin/i,
  /libfrida/i,
  /libgadget/i,
  /assets\/(mod|menu|cheat)/i,
  /classes2\.dex$/i
]

export function createManifest (apkPath, description = '') {
  const entries = readApk(apkPath)
  return {
    version: 1,
    description,
    entries: entries
      .map((entry) => ({ name: entry.name, crc: entry.crc, size: entry.size }))
      .sort((a, b) => a.name.localeCompare(b.name))
  }
}

export function verify (apkPath, manifest) {
  const entries = readApk(apkPath)
  const expected = new Map(manifest.entries.map((entry) => [entry.name, entry]))
  const actual = new Map(entries.map((entry) => [entry.name, entry]))

  const unexpected = []
  const missing = []
  const changed = []
  const suspicious = []

  for (const entry of actual.values()) {
    if (MOD_PATTERNS.some((pattern) => pattern.test(entry.name))) suspicious.push(entry.name)
    if (!expected.has(entry.name)) {
      unexpected.push(entry.name)
      continue
    }
    const wanted = expected.get(entry.name)
    if (wanted.crc !== entry.crc || wanted.size !== entry.size) changed.push(entry.name)
  }

  for (const name of expected.keys()) {
    if (!actual.has(name)) missing.push(name)
  }

  const ok = unexpected.length === 0 && missing.length === 0 && changed.length === 0

  return {
    ok,
    repacked: !ok || suspicious.length > 0,
    unexpected: unexpected.sort(),
    missing: missing.sort(),
    changed: changed.sort(),
    suspicious: suspicious.sort(),
    entries: entries.length
  }
}

export function formatResult (result) {
  const lines = []
  lines.push(`entries: ${result.entries}`)
  lines.push(result.ok ? 'matches the build manifest' : 'does not match the build manifest')
  if (result.unexpected.length) lines.push(`  unexpected: ${result.unexpected.slice(0, 20).join(', ')}`)
  if (result.missing.length) lines.push(`  missing: ${result.missing.slice(0, 20).join(', ')}`)
  if (result.changed.length) lines.push(`  modified: ${result.changed.slice(0, 20).join(', ')}`)
  if (result.suspicious.length) lines.push(`  known mod artefacts: ${result.suspicious.join(', ')}`)
  return lines.join('\n')
}
