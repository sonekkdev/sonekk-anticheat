import { spawnSync } from 'node:child_process'

const suites = [
  ['guard server', 'guard/server/test/guard.test.js'],
  ['motion', 'motion/test/movement.test.js'],
  ['seal', 'seal/test/seal.test.js'],
  ['antiadb', 'antiadb/test/watch.test.js']
]

let failed = 0
for (const [name, file] of suites) {
  const result = spawnSync(process.execPath, ['--test', file], { stdio: 'inherit' })
  if (result.status !== 0) {
    failed += 1
    console.error(`\n${name}: FAILED`)
  } else {
    console.log(`\n${name}: ok`)
  }
}

if (failed > 0) {
  console.error(`\n${failed} suite(s) failed`)
  process.exit(1)
}
console.log('\nall node suites passed')
