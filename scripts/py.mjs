// Runs the project's Python (.venv) with the given arguments, so nobody has to "activate" anything.
//   node scripts/py.mjs -m pytest
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export const venvPython = process.platform === 'win32'
  ? path.join(root, '.venv', 'Scripts', 'python.exe')
  : path.join(root, '.venv', 'bin', 'python')

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  if (!existsSync(venvPython)) {
    console.error('\n  Python environment not found. Run this first:\n\n    npm run setup\n')
    process.exit(1)
  }
  const child = spawn(venvPython, process.argv.slice(2), { stdio: 'inherit', cwd: root })
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill(sig))
  child.on('exit', (code) => process.exit(code ?? 1))
}
