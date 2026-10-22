// One-time setup: finds Python 3.11+, creates .venv, installs everything, and writes a .env.
//   npm run setup
// Safe to run again at any time; it repairs a broken .venv and never overwrites an existing .env.
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { venvPython } from './py.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const isWin = process.platform === 'win32'
const step = (msg) => console.log(`\n▸ ${msg}`)
const fail = (msg) => { console.error(`\n✗ ${msg}\n`); process.exit(1) }
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { cwd: root, encoding: 'utf8', ...opts })

// 1. Node
const [nodeMajor] = process.versions.node.split('.').map(Number)
if (nodeMajor < 20) fail(`Node ${process.versions.node} is too old. Install Node 20 or newer from https://nodejs.org`)

// 2. A Python 3.11+ to build the virtual environment from
function findPython() {
  const candidates = isWin
    ? [['py', '-3.13'], ['py', '-3.12'], ['py', '-3.11'], ['python'], ['python3']]
    : [['python3.13'], ['python3.12'], ['python3.11'], ['python3'], ['python']]
  for (const [cmd, ...pre] of candidates) {
    const r = run(cmd, [...pre, '-c', 'import sys; print("%d.%d" % sys.version_info[:2])'])
    const version = r.status === 0 ? r.stdout.trim() : ''
    const [major, minor] = version.split('.').map(Number)
    if (major === 3 && minor >= 11) return { cmd, pre, version }
  }
  return null
}

step('Checking Python')
const py = findPython()
if (!py) fail('Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"), then run npm run setup again.')
console.log(`  Using Python ${py.version} (${[py.cmd, ...py.pre].join(' ')})`)

// 3. .venv (recreated if missing or broken, e.g. after an interrupted pip upgrade)
const venvWorks = existsSync(venvPython) && run(venvPython, ['-m', 'pip', '--version']).status === 0
if (!venvWorks) {
  if (existsSync(path.join(root, '.venv'))) {
    step('Repairing the Python environment (.venv)')
    rmSync(path.join(root, '.venv'), { recursive: true, force: true })
  } else {
    step('Creating the Python environment (.venv)')
  }
  if (run(py.cmd, [...py.pre, '-m', 'venv', '.venv'], { stdio: 'inherit' }).status !== 0) fail('Could not create .venv.')
}

// 4. Python packages
step('Installing Python packages (first time takes a few minutes)')
const pip = run(venvPython, ['-m', 'pip', 'install', '--disable-pip-version-check', '-q', '-r', 'requirements.txt'], { stdio: 'inherit' })
if (pip.status !== 0) fail('Installing Python packages failed. The error is shown above.')

// 5. JavaScript packages (always run: it is quick when nothing changed, and picks up package.json updates)
step('Installing JavaScript packages')
const npm = process.env.npm_execpath
  ? run(process.execPath, [process.env.npm_execpath, 'install', '--no-fund', '--no-audit'], { stdio: 'inherit' })
  : run(isWin ? 'npm.cmd' : 'npm', ['install', '--no-fund', '--no-audit'], { stdio: 'inherit', shell: isWin })
if (npm.status !== 0) fail('npm install failed. The error is shown above.')

// 6. .env (written once; edit it to add MongoDB, GitHub and email settings)
const envPath = path.join(root, '.env')
if (!existsSync(envPath)) {
  step('Creating .env')
  writeFileSync(envPath, `# Local settings. Never commit this file.

# Login token signing key (generated for you)
SECRET_KEY=${randomBytes(36).toString('base64url')}

# MongoDB. Leave empty to use a throwaway in-memory database, or paste a MongoDB Atlas connection string:
# MONGODB_URI=mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/
MONGODB_URI=
MONGODB_DB=ghosttrace

# GitHub token (classic, no scopes) raises the GitHub limit from 60 to 5,000 requests an hour
GITHUB_TOKEN=

# Email alerts (optional). Gmail: smtp.gmail.com + an app password
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=GhostTrace <alerts@example.com>
`)
} else {
  console.log('\n  .env already exists, left unchanged')
}

console.log(`
✓ Setup complete.

  npm run dev     start the app  →  http://localhost:5173
  npm test        run the tests
`)
