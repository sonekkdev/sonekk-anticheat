export const WATCHED = ['refreshRate','debugOculusRefreshRate','adbWifiEnabled','adbPort5555','screenOffTimeout','stayOnWhilePluggedIn','usbAttached']

/**
 * Compares two snapshots taken while the game runs. The app cannot see adb itself,
 * so it watches the effects adb commands leave behind, such as a refresh rate change
 * made by "set refresh rate 90" in the middle of a session.
 */
export function assess (before, after, options = {}) {
  const changes = []
  for (const key of WATCHED) {
    if (before[key] === undefined || after[key] === undefined) continue
    if (before[key] === after[key]) continue
    changes.push({ key, from: before[key], to: after[key] })
  }

  const developerMode = Boolean(after.developerMode)
  if (changes.length === 0) {
    return developerMode
      ? { action: 'notice', reasons: [], notice: 'Developer mode is on. Turn off ADB while playing.' }
      : { action: 'allow', reasons: [] }
  }

  return {
    action: 'kick',
    reasons: changes.map((change) => `${change.key}: ${change.from} -> ${change.to}`),
    notice: developerMode ? 'Developer mode is on. Turn off ADB while playing.' : null,
    changes
  }
}
