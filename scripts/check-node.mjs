// Vite 8 (and its Rolldown bundler) needs Node 20.19+ or 22.12+. On older versions npm silently skips the
// native bundler binary, and Vite then fails with "Cannot find native binding". Catch that early with a clear message.
const [major, minor] = process.versions.node.split('.').map(Number)
const ok = (major === 20 && minor >= 19) || (major === 22 && minor >= 12) || major >= 23
if (!ok) {
  console.error(`\n✗ Node ${process.versions.node} is too old for this project. It needs Node 20.19+ or 22.12+ (24 LTS is ideal).`)
  console.error('  1. Install the current LTS from https://nodejs.org (or: winget upgrade OpenJS.NodeJS.LTS)')
  console.error('  2. Close and reopen the terminal, check with: node -v')
  console.error('  3. Delete node_modules, then run: npm run setup\n')
  process.exit(1)
}
