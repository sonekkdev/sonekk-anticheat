#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { createManifest, formatResult, verify } from './seal.js'

const USAGE = `sonekk-seal <command> <apk> [options]

  sign   <apk> -o seal.json    write the manifest for a build you trust
  verify <apk> --manifest f    compare a downloaded APK against the manifest
  scan   <apk>                 list mod artefacts and lib contents only

Options: --json`

const [command, apk, ...rest] = process.argv.slice(2)
const json = process.argv.includes('--json')
const outIndex = rest.indexOf('-o')
const manifestIndex = rest.indexOf('--manifest')
const output = outIndex >= 0 ? rest[outIndex + 1] : null
const manifestPath = manifestIndex >= 0 ? rest[manifestIndex + 1] : null

if (!command || !apk) {
  console.log(USAGE)
  process.exit(2)
}

try {
  if (command === 'sign') {
    const manifest = createManifest(apk)
    const target = output ?? 'seal.json'
    writeFileSync(target, JSON.stringify(manifest, null, 2))
    console.log(`manifest written to ${target} (${manifest.entries.length} entries)`)
    process.exit(0)
  }

  if (command === 'verify') {
    if (!manifestPath) {
      console.error('verify needs --manifest <file>')
      process.exit(2)
    }
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    const result = verify(apk, manifest)
    if (json) console.log(JSON.stringify(result, null, 2))
    else console.log(formatResult(result))
    process.exit(result.repacked ? 1 : 0)
  }

  if (command === 'scan') {
    const manifest = createManifest(apk)
    const result = verify(apk, manifest)
    if (json) console.log(JSON.stringify(result, null, 2))
    else console.log(formatResult(result))
    process.exit(result.suspicious.length > 0 ? 1 : 0)
  }

  console.log(USAGE)
  process.exit(2)
} catch (error) {
  console.error(String(error?.message ?? error))
  process.exit(2)
}
