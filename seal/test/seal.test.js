import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

import { createManifest, verify } from '../src/seal.js'
import { readApk } from '../src/zip.js'

const fixture = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))

test('reads zip entries', () => {
  const entries = readApk(fixture('clean.apk'))
  assert.ok(entries.length >= 4)
  assert.ok(entries.some((entry) => entry.name.endsWith('libil2cpp.so')))
})

test('a clean apk matches its own manifest', () => {
  const apk = fixture('clean.apk')
  const result = verify(apk, createManifest(apk))
  assert.equal(result.ok, true)
  assert.equal(result.repacked, false)
})

test('an injected library is caught', () => {
  const result = verify(fixture('modded.apk'), createManifest(fixture('clean.apk')))
  assert.equal(result.ok, false)
  assert.ok(result.unexpected.some((name) => name.includes('libmodmenu.so')))
  assert.ok(result.suspicious.some((name) => name.includes('libmodmenu.so')))
  assert.equal(result.repacked, true)
})

test('a missing file is caught', () => {
  const result = verify(fixture('clean.apk'), createManifest(fixture('modded.apk')))
  assert.equal(result.ok, false)
  assert.ok(result.missing.some((name) => name.includes('libmodmenu.so')))
})

test('the same apk can be signed and verified again', () => {
  const apk = fixture('modded.apk')
  assert.equal(verify(apk, createManifest(apk)).ok, true)
})
