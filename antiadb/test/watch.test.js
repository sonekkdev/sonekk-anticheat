import assert from 'node:assert/strict'
import { test } from 'node:test'
import { assess } from '../src/watch.js'

const base = { refreshRate: 72, adbWifiEnabled: 0, adbPort5555: false, developerMode: false }

test('quiet session is allowed', () => {
  assert.equal(assess(base, { ...base }).action, 'allow')
})

test('developer mode only shows a notice', () => {
  const result = assess(base, { ...base, developerMode: true })
  assert.equal(result.action, 'notice')
  assert.match(result.notice, /Turn off ADB/)
})

test('a refresh rate change mid session kicks', () => {
  const result = assess(base, { ...base, refreshRate: 90 })
  assert.equal(result.action, 'kick')
  assert.match(result.reasons[0], /refreshRate: 72 -> 90/)
})

test('developer mode does not prevent a kick', () => {
  const result = assess(base, { ...base, developerMode: true, refreshRate: 90 })
  assert.equal(result.action, 'kick')
  assert.ok(result.notice)
})

test('adb appearing on 5555 kicks', () => {
  const result = assess(base, { ...base, adbPort5555: true })
  assert.equal(result.action, 'kick')
})

test('usb being plugged mid session is a signal', () => {
  assert.equal(assess({ ...base, usbAttached: false }, { ...base, usbAttached: true }).action, 'kick')
})

test('never bans', () => {
  const result = assess(base, { ...base, refreshRate: 90, adbPort5555: true })
  assert.notEqual(result.action, 'ban')
})

