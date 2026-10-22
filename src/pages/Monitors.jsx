import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { Building2, Eye, FolderGit2, Mail, Play, Trash2, User as UserIcon } from 'lucide-react'
import { api } from '../lib/api'
import { TARGET_LABELS, timeAgo } from '../lib/format'
import { EmptyState, PageHeader, Spinner } from '../components/ui'
import { useConfirm, useToast } from '../components/Toast'

// The original Monitors layout (four-way type picker, bordered cards) in the app's black, grey and white scheme.
const TYPES = [
  { id: 'github_org', label: 'GitHub org', icon: Building2, placeholder: 'acme-corp' },
  { id: 'github_user', label: 'GitHub user', icon: UserIcon, placeholder: 'octocat' },
  { id: 'github_repo', label: 'Repository', icon: FolderGit2, placeholder: 'owner/repo' },
  { id: 'email', label: 'Email', icon: Mail, placeholder: 'security@company.com' },
]

const CARD = 'rounded-[28px] bg-[#121212] overflow-hidden'

export default function Monitors() {
  const toast = useToast()
  const confirm = useConfirm()
  const navigate = useNavigate()
  const [items, setItems] = useState(null)
  const [type, setType] = useState('github_org')
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [running, setRunning] = useState(null)

  useEffect(() => { api('/api/monitors').then(setItems).catch((e) => toast(e.message, 'error')) }, [toast])

  async function runNow(m, { quiet } = {}) {
    setRunning(m.id)
    try {
      const r = await api(`/api/monitors/${m.id}/run`, { method: 'POST' })
      setItems((x) => x.map((y) => (y.id === m.id ? r.monitor : y)))
      if (r.scan_id) navigate(`/app/scans/${r.scan_id}`)
      else if (!quiet) toast('Checked for new breaches')
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setRunning(null)
    }
  }

  async function add(e) {
    e.preventDefault()
    setBusy(true)
    try {
      const m = await api('/api/monitors', { method: 'POST', body: { target_type: type, target: target.trim() } })
      setItems((x) => [m, ...x])
      setTarget('')
      toast('Monitor added. A baseline scan has started.')
      runNow(m, { quiet: true }) // baseline: email checks finish here, GitHub opens the live scan
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function toggle(m) {
    try {
      const u = await api(`/api/monitors/${m.id}`, { method: 'PATCH', body: { enabled: !m.enabled } })
      setItems((x) => x.map((y) => (y.id === m.id ? u : y)))
    } catch (e) { toast(e.message, 'error') }
  }

  async function remove(m) {
    if (!(await confirm({ title: `Stop monitoring ${m.target}?`, confirmLabel: 'Stop', destructive: true }))) return
    await api(`/api/monitors/${m.id}`, { method: 'DELETE' })
    setItems((x) => x.filter((y) => y.id !== m.id))
  }

  const t = TYPES.find((x) => x.id === type)
  return (
    <>
      <PageHeader title="Monitors" description="GhostTrace re-scans monitored targets on a schedule and emails you when a new credential or breach appears." />
      <div className="grid items-start gap-6 lg:grid-cols-[360px_1fr]">
        <div className={clsx(CARD, 'p-5')}>
          <form onSubmit={add} className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              {TYPES.map(({ id, label, icon: Icon }) => (
                <button type="button" key={id} onClick={() => setType(id)}
                  className={clsx('flex items-center gap-2 rounded-2xl px-3 py-2.5 text-xs transition',
                    type === id ? 'bg-[#3a3a3a] text-white' : 'bg-[#1e1e1e] text-label-2 hover:bg-[#2a2a2a]')}>
                  <Icon className="h-4 w-4" /> {label}
                </button>
              ))}
            </div>
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-label-2">Target</span>
              <input required value={target} onChange={(e) => setTarget(e.target.value)} placeholder={t.placeholder}
                autoCapitalize="off" autoCorrect="off" spellCheck={false}
                className="w-full rounded-2xl bg-fill-3 px-3.5 py-2.5 font-mono text-sm text-label transition placeholder:text-label-4 focus:bg-fill-2 focus:outline-none" />
            </label>
            <button type="submit" disabled={busy}
              className="press flex h-12 w-full items-center justify-center gap-2 rounded-full bg-white text-callout font-semibold text-black transition hover:bg-[#e6e6e6] disabled:opacity-40">
              {busy ? <Spinner className="h-4 w-4" color="currentColor" /> : <Eye className="h-4 w-4" />} Start monitoring
            </button>
          </form>
        </div>

        <div className={CARD}>
          <div className="px-5 py-4 text-sm font-semibold text-label">Active monitors</div>
          {!items ? <div className="space-y-2 p-4"><div className="skeleton h-12" /><div className="skeleton h-12" /></div>
            : items.length === 0 ? (
              <EmptyState icon={Eye} title="Nothing monitored yet">Add your GitHub organization or team emails to get alerted on new leaks.</EmptyState>
            ) : (
              <ul className="divide-y divide-white/10">
                {items.map((m) => {
                  const Icon = (TYPES.find((x) => x.id === m.target_type) || TYPES[0]).icon
                  return (
                    <li key={m.id} className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex min-w-0 items-center gap-3">
                        <div className="rounded-xl bg-black p-2"><Icon className="h-4 w-4 text-white" /></div>
                        <div className="min-w-0">
                          <div className="truncate font-mono text-sm text-white">{m.target}</div>
                          <div className="text-xs text-label-3">{TARGET_LABELS[m.target_type]} · last run {timeAgo(m.last_run_at)}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button type="button" onClick={() => toggle(m)} className={clsx('relative h-5 w-9 rounded-full transition', m.enabled ? 'bg-white' : 'bg-fill-1')} aria-label={`Monitor ${m.target}`} aria-pressed={m.enabled}>
                          <span className={clsx('absolute top-0.5 h-4 w-4 rounded-full transition', m.enabled ? 'left-[18px] bg-black' : 'left-0.5 bg-white')} />
                        </button>
                        <button type="button" onClick={() => runNow(m)} disabled={running === m.id}
                          className="flex h-10 items-center gap-2 rounded-full bg-[#1e1e1e] px-5 text-callout font-semibold text-white transition hover:bg-[#2a2a2a] disabled:opacity-40">
                          {running === m.id ? <Spinner className="h-3.5 w-3.5" color="currentColor" /> : <Play className="h-3.5 w-3.5" />} Run now
                        </button>
                        <button type="button" onClick={() => remove(m)} className="rounded-full p-2 text-label-3 transition hover:bg-white/10 hover:text-sev-critical" aria-label="Delete monitor" title="Remove"><Trash2 className="h-4 w-4" /></button>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
        </div>
      </div>
    </>
  )
}
