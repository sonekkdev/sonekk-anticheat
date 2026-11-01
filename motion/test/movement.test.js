import assert from 'node:assert/strict'
import http from 'node:http'
import { test } from 'node:test'

import { analyseSamples, createMovementHandler, StrikeStore } from '../src/movement.js'

// 10 Hz samples, walking at 4 m/s along +X.
function walk (count, speed = 4, options = {}) {
  const samples = []
  for (let i = 0; i < count; i += 1) {
    samples.push({
      t: i * 100,
      x: i * 0.1 * speed,
      y: 1,
      z: 0,
      grounded: true,
      groundY: 0,
      ...options
    })
  }
  return samples
}

test('normal walking is clean', () => {
  assert.equal(analyseSamples(walk(30)).length, 0)
})

test('running faster than the limit is caught', () => {
  const violations = analyseSamples(walk(30, 14))
  assert.ok(violations.some((violation) => violation.type === 'speed'))
})

test('flying without ground contact is caught', () => {
  const samples = []
  for (let i = 0; i < 20; i += 1) {
    samples.push({ t: i * 100, x: 0, y: 1 + i * 0.6, z: 0, grounded: false })
  }
  const violations = analyseSamples(samples)
  assert.ok(violations.some((violation) => violation.type === 'fly'))
})

test('a teleport is caught', () => {
  const samples = walk(10)
  samples[5] = { ...samples[5], x: 40 }
  const violations = analyseSamples(samples)
  assert.ok(violations.some((violation) => violation.type === 'teleport'))
})

test('respawn and knockback flags are ignored', () => {
  const samples = walk(20)
  samples[6] = { ...samples[6], x: 80, flags: ['respawn'] }
  samples[10] = { ...samples[10], y: 9, flags: ['knockback'] }
  const violations = analyseSamples(samples)
  assert.equal(violations.filter((violation) => violation.type === 'teleport').length, 0)
})

test('claiming to stand above the floor is caught', () => {
  const samples = walk(10)
  samples[4] = { ...samples[4], y: 6, groundY: 0, grounded: true }
  const violations = analyseSamples(samples)
  assert.ok(violations.some((violation) => violation.type === 'ground'))
})

test('strike ladder: kick twice, ban third', () => {
  const store = new StrikeStore()
  const violations = [{ type: 'fly', detail: '', at: 0 }]
  assert.equal(store.record('p1', violations, 1000).action, 'kick')
  assert.equal(store.record('p1', violations, 2000).action, 'kick')
  const third = store.record('p1', violations, 3000)
  assert.equal(third.action, 'ban')
  assert.equal(third.strikes, 3)
})

test('strikes decay after the window', () => {
  const store = new StrikeStore({ decayMs: 1000 })
  store.record('p1', [{ type: 'fly' }], 1000)
  store.record('p1', [{ type: 'fly' }], 1500)
  const later = store.record('p1', [{ type: 'fly' }], 5000)
  assert.equal(later.strikes, 1)
  assert.equal(later.action, 'kick')
})

test('handler allows a fresh player inside the grace window', async () => {
  const handle = createMovementHandler()
  const server = http.createServer((request, response) => handle(request, response))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  const response = await fetch(`http://127.0.0.1:${port}/`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      playerId: 'fresh',
      joinedAt: Date.now(),
      samples: Array.from({ length: 20 }, (_, i) => ({ t: i * 100, x: 0, y: 1 + i, z: 0, grounded: false }))
    })
  })

  assert.equal(response.status, 200)
  assert.equal((await response.json()).action, 'allow')
  await new Promise((resolve) => server.close(resolve))
})

test('handler escalates to ban after three events', async () => {
  const store = new StrikeStore({ graceMs: 0 })
  const handle = createMovementHandler({ store })
  const server = http.createServer((request, response) => handle(request, response))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  const body = JSON.stringify({
    playerId: 'flyer',
    samples: Array.from({ length: 20 }, (_, i) => ({ t: i * 100, x: 0, y: 1 + i, z: 0, grounded: false }))
  })

  const actions = []
  for (let i = 0; i < 3; i += 1) {
    const response = await fetch(`http://127.0.0.1:${port}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body
    })
    actions.push((await response.json()).action)
  }

  assert.deepEqual(actions, ['kick', 'kick', 'ban'])
  await new Promise((resolve) => server.close(resolve))
})
