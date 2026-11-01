import http from 'node:http'
import { readFileSync, existsSync } from 'node:fs'

import { createApp } from './app.js'
import { rootsFromPem } from './attestation.js'

const port = Number(process.env.PORT ?? 8787)
const secret = process.env.SONEKK_GUARD_SECRET ?? ''
const requireChallenge = process.env.SONEKK_REQUIRE_CHALLENGE !== 'false'
const requireAttestation = process.env.SONEKK_REQUIRE_ATTESTATION === 'true'
const rootsPath = process.env.SONEKK_ATTESTATION_ROOTS ?? ''

if (!secret) {
  console.warn('[sonekk-guard] SONEKK_GUARD_SECRET is empty, signature checks are disabled')
}

const roots = rootsPath && existsSync(rootsPath) ? rootsFromPem([readFileSync(rootsPath, 'utf8')]) : []
if (requireAttestation && roots.length === 0) {
  console.warn('[sonekk-guard] attestation required but no roots loaded, every report will be rejected')
}

const handle = createApp({
  secret,
  roots,
  requireChallenge,
  requireAttestation,
  onReport: (report) => {
    console.log(
      `[sonekk-guard] ${report.verdict} score=${report.score} attested=${report.attested} ` +
        `findings=${report.findings.map((finding) => finding.id).join(',') || 'none'}`
    )
  }
})

http
  .createServer((req, res) => handle(req, res))
  .listen(port, () => {
    console.log(`[sonekk-guard] listening on http://127.0.0.1:${port}`)
  })
