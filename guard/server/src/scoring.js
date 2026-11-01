// Scoring lives on the server on purpose. The client sends observations, never a verdict,
// and the weight field it reports is ignored.

export const WEIGHTS = {
  'frida.maps': 90,
  'frida.module': 80,
  'frida.thread': 85,
  'frida.port': 70,
  'frida.anon_exec': 25,
  'root.paths': 60,
  'root.mounts': 45,
  'root.props': 35,
  'debug.tracer': 50,
  'integrity.self_hash': 95,
  'integrity.symbol_hook': 95,
  'integrity.signature': 90,
  'integrity.memory_text': 95,
  'instrumentation.inconsistent': 70,
  'emulator.host': 20,
  'app.debuggable': 15
}

const UNKNOWN_WEIGHT = 10
const MAX_FINDINGS = 64

/**
 * @param {unknown} findings
 * @returns {{ id: string, weight: number, known: boolean }[]}
 */
export function normaliseFindings (findings) {
  if (!Array.isArray(findings)) return []
  const seen = new Set()
  const out = []
  for (const raw of findings.slice(0, MAX_FINDINGS)) {
    if (!raw || typeof raw !== 'object') continue
    const id = typeof raw.id === 'string' ? raw.id.slice(0, 64) : ''
    if (!id || seen.has(id)) continue
    seen.add(id)
    const known = Object.prototype.hasOwnProperty.call(WEIGHTS, id)
    out.push({ id, weight: known ? WEIGHTS[id] : UNKNOWN_WEIGHT, known })
  }
  return out
}

export function scoreReport (findings) {
  const normalised = normaliseFindings(findings)
  const score = normalised.reduce((total, item) => total + item.weight, 0)
  return { score, findings: normalised }
}

/**
 * Thresholds are deliberately generous. A single medium finding should never ban anyone.
 * @param {number} score
 */
export function decide (score) {
  if (score >= 100) return 'block'
  if (score >= 50) return 'review'
  if (score >= 20) return 'watch'
  return 'clean'
}
