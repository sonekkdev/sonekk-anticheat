import assert from 'node:assert/strict'
import http from 'node:http'
import { createHmac, sign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { createApp } from '../src/app.js'
import { rootsFromPem } from '../src/attestation.js'
import { ChallengeStore } from '../src/challenge.js'
import { buildKeyDescription } from '../tools/make-attestation-fixture.mjs'
import { parseKeyDescription } from '../src/keydescription.js'
import { RateLimiter } from '../src/ratelimit.js'
import { decide, scoreReport } from '../src/scoring.js'
import { verifySignature } from '../src/verify.js'

const SECRET = 'test-secret'
const FIXED_CHALLENGE = '0123456789abcdef0123456789abcdef'

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')
const derBase64 = (pem) => pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')

const rootPem = fixture('root.pem')
const otherRootPem = fixture('other-root.pem')
const attestedLeafPem = fixture('attested-leaf.pem')
const attestedLeafKey = fixture('attested-leaf.key')
const unlockedLeafPem = fixture('unlocked-leaf.pem')
const unlockedLeafKey = fixture('unlocked-leaf.key')

async function withServer (options, run) {
  const handle = createApp(options)
  const server = http.createServer((req, res) => handle(req, res))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  try {
    await run(`http://127.0.0.1:${port}`)
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
}

async function challenge (base) {
  const response = await fetch(`${base}/v1/challenge`, { method: 'POST' })
  assert.equal(response.status, 200)
  return (await response.json()).nonce
}

async function postReport (base, payload, secret = SECRET) {
  const body = JSON.stringify(payload)
  const signature = createHmac('sha256', secret).update(body).digest('hex')
  return fetch(`${base}/v1/report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-sonekk-signature': signature },
    body
  })
}

// A server whose challenge store already knows the fixture's challenge, so a
// certificate generated at fixture time can be bound to it.
async function withSeededServer (options, run) {
  const challenges = new ChallengeStore()
  challenges.remember(FIXED_CHALLENGE)
  return withServer({ ...options, challenges }, run)
}

async function attestedReport (
  base,
  { certPem = attestedLeafPem, keyPem = attestedLeafKey, nonce, chainPem } = {}
) {
  const chosen = nonce ?? (await challenge(base))
  const signature = sign('sha256', Buffer.from(chosen, 'utf8'), keyPem).toString('base64')
  return postReport(base, {
    v: 1,
    nonce: chosen,
    findings: [],
    attestation: { chain: (chainPem ?? [certPem, rootPem]).map(derBase64), signature }
  })
}

test('known findings use the server weight table', () => {
  const { score } = scoreReport([{ id: 'frida.maps', w: 1 }, { id: 'root.paths', w: 9999 }])
  assert.equal(score, 150, 'client weights are ignored')
})

test('new detections are scored', () => {
  const { score } = scoreReport([
    { id: 'frida.thread' },
    { id: 'emulator.host' },
    { id: 'app.debuggable' },
    { id: 'integrity.memory_text' },
    { id: 'instrumentation.inconsistent' }
  ])
  assert.equal(score, 85 + 20 + 15 + 95 + 70)
})

test('unknown findings carry a small weight instead of failing', () => {
  const { score, findings } = scoreReport([{ id: 'future.check' }])
  assert.equal(score, 10)
  assert.equal(findings[0].known, false)
})

test('duplicate findings are counted once', () => {
  const { score } = scoreReport([{ id: 'root.props' }, { id: 'root.props' }])
  assert.equal(score, 35)
})

test('thresholds are generous', () => {
  assert.equal(decide(19), 'clean')
  assert.equal(decide(20), 'watch')
  assert.equal(decide(49), 'watch')
  assert.equal(decide(50), 'review')
  assert.equal(decide(99), 'review')
  assert.equal(decide(100), 'block')
})

test('signature verification rejects tampering', () => {
  const body = Buffer.from('{"v":1,"findings":[]}')
  const good = createHmac('sha256', SECRET).update(body).digest('hex')
  assert.equal(verifySignature(body, good, SECRET), true)
  assert.equal(verifySignature(Buffer.from('{"v":1,"findings":[1]}'), good, SECRET), false)
  assert.equal(verifySignature(body, good, 'wrong-secret'), false)
})

test('challenges are single use', () => {
  const store = new ChallengeStore()
  const nonce = store.issue()
  assert.equal(nonce.length, 32)
  assert.equal(store.consume(nonce), true)
  assert.equal(store.consume(nonce), false, 'replay rejected')
})

test('expired challenges are rejected', () => {
  const store = new ChallengeStore({ ttlMs: -1000 })
  const nonce = store.issue()
  assert.equal(store.consume(nonce), false)
})

test('rate limiter blocks after the limit', () => {
  const limiter = new RateLimiter({ limit: 2, windowMs: 60_000 })
  assert.equal(limiter.allow('a'), true)
  assert.equal(limiter.allow('a'), true)
  assert.equal(limiter.allow('a'), false)
  assert.equal(limiter.allow('b'), true)
})

test('key description parser reads the TEE fields', () => {
  const der = buildKeyDescription({
    challenge: FIXED_CHALLENGE,
    verifiedBootState: 0,
    deviceLocked: true
  })
  // findExtensionValue expects a certificate, so parse the description directly.
  const parsed = parseKeyDescription(der)
  assert.equal(parsed.challenge, FIXED_CHALLENGE)
  assert.equal(parsed.verifiedBootState, 0)
  assert.equal(parsed.bootStateName, 'verified')
  assert.equal(parsed.deviceLocked, true)
})

test('endpoint issues a challenge', async () => {
  await withServer({ secret: SECRET }, async (base) => {
    const nonce = await challenge(base)
    assert.equal(nonce.length, 32)
  })
})

test('report without a challenge is rejected', async () => {
  await withServer({ secret: SECRET }, async (base) => {
    const response = await postReport(base, { v: 1, findings: [{ id: 'frida.maps' }] })
    assert.equal(response.status, 401)
    assert.equal((await response.json()).error, 'bad_challenge')
  })
})

test('report scores server side and ignores the client verdict', async () => {
  await withServer({ secret: SECRET }, async (base) => {
    const nonce = await challenge(base)
    const response = await postReport(base, {
      v: 1,
      sdk: '0.2.0',
      nonce,
      score: 0,
      verdict: 'clean',
      findings: [{ id: 'frida.maps' }, { id: 'root.paths' }, { id: 'debug.tracer' }]
    })
    assert.equal(response.status, 200)
    const json = await response.json()
    assert.equal(json.score, 200)
    assert.equal(json.verdict, 'block')
    assert.equal(json.attested, false)
  })
})

test('replaying a captured report is rejected', async () => {
  await withServer({ secret: SECRET }, async (base) => {
    const nonce = await challenge(base)
    const payload = { v: 1, nonce, findings: [{ id: 'root.props' }] }
    assert.equal((await postReport(base, payload)).status, 200)
    assert.equal((await postReport(base, payload)).status, 401)
  })
})

test('bad signature is rejected', async () => {
  await withServer({ secret: SECRET }, async (base) => {
    const nonce = await challenge(base)
    const response = await postReport(base, { v: 1, nonce, findings: [] }, 'wrong-secret')
    assert.equal(response.status, 401)
  })
})

test('valid attestation with a matching challenge is trusted', async () => {
  await withSeededServer({ secret: SECRET, roots: rootsFromPem([rootPem]) }, async (base) => {
    const response = await attestedReport(base, { nonce: FIXED_CHALLENGE })
    assert.equal(response.status, 200)
    const json = await response.json()
    assert.equal(json.attested, true)
    assert.equal(json.trusted, true)
    assert.equal(json.bootState, 'verified')
  })
})

test('attestation bound to a different challenge is rejected', async () => {
  await withServer({ secret: SECRET, roots: rootsFromPem([rootPem]) }, async (base) => {
    // Fresh random nonce, but the certificate carries the fixture challenge.
    const response = await attestedReport(base)
    const json = await response.json()
    assert.equal(json.attested, false)
    assert.equal(json.trusted, false)
  })
})

test('unlocked bootloader is attested but not trusted', async () => {
  await withSeededServer({ secret: SECRET, roots: rootsFromPem([rootPem]) }, async (base) => {
    const response = await attestedReport(base, {
      certPem: unlockedLeafPem,
      keyPem: unlockedLeafKey,
      nonce: FIXED_CHALLENGE
    })
    const json = await response.json()
    assert.equal(json.attested, true)
    assert.equal(json.trusted, false)
    assert.equal(json.bootState, 'unverified')
  })
})

test('required attestation rejects an unlocked device', async () => {
  await withSeededServer(
    { secret: SECRET, roots: rootsFromPem([rootPem]), requireAttestation: true },
    async (base) => {
      const response = await attestedReport(base, {
        certPem: unlockedLeafPem,
        keyPem: unlockedLeafKey,
        nonce: FIXED_CHALLENGE
      })
      assert.equal(response.status, 401)
      assert.equal((await response.json()).error, 'attestation_required')
    }
  )
})

test('attestation signed by the wrong key is not accepted', async () => {
  await withSeededServer({ secret: SECRET, roots: rootsFromPem([rootPem]) }, async (base) => {
    const response = await attestedReport(base, {
      keyPem: fixture('other-root.key'),
      nonce: FIXED_CHALLENGE
    })
    assert.equal((await response.json()).attested, false)
  })
})

test('attestation anchored to an untrusted root is not accepted', async () => {
  await withSeededServer({ secret: SECRET, roots: rootsFromPem([otherRootPem]) }, async (base) => {
    const response = await attestedReport(base, { nonce: FIXED_CHALLENGE })
    assert.equal((await response.json()).attested, false)
  })
})

test('expired attestation is not accepted', async () => {
  await withSeededServer(
    { secret: SECRET, roots: rootsFromPem([rootPem]), now: () => Date.parse('2099-01-01T00:00:00Z') },
    async (base) => {
      const response = await attestedReport(base, { nonce: FIXED_CHALLENGE })
      assert.equal((await response.json()).attested, false)
    }
  )
})

test('required attestation blocks an unattested client', async () => {
  await withServer(
    { secret: SECRET, roots: rootsFromPem([rootPem]), requireAttestation: true },
    async (base) => {
      const nonce = await challenge(base)
      const response = await postReport(base, { v: 1, nonce, findings: [] })
      assert.equal(response.status, 401)
      assert.equal((await response.json()).error, 'attestation_required')
    }
  )
})

test('malformed body is rejected without crashing', async () => {
  await withServer({ secret: SECRET }, async (base) => {
    const body = 'not json'
    const signature = createHmac('sha256', SECRET).update(body).digest('hex')
    const response = await fetch(`${base}/v1/report`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-sonekk-signature': signature },
      body
    })
    assert.equal(response.status, 400)
  })
})
