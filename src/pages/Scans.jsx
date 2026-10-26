import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { AnimatePresence, motion } from 'motion/react'
import { Building2, ClipboardPaste, FileArchive, FolderGit2, HardDrive, History, Lock, Radar, Trash2, Upload, User as UserIcon } from 'lucide-react'
import { api } from '../lib/api'
import { useMeta } from '../lib/meta'
import { Github } from '../components/icons'
import { plural, TARGET_LABELS, timeAgo } from '../lib/format'
import { Button, EmptyState, Field, Glass, Group, PageHeader, RiskMeter, Segmented, StatusBadge, Switch, spring } from '../components/ui'
import { useConfirm, useToast } from '../components/Toast'

/** Work out what was pasted: a repo (owner/name or any github.com/owner/name URL) or just an account name. */
function parseTarget(raw) {
  const v = raw.trim().replace(/^https?:\/\//, '').replace(/^(www\.)?github\.com\//, '').replace(/\.git$/, '').replace(/^@/, '').replace(/\/+$/, '')
  if (!v) return { kind: null }
  const parts = v.split('/').filter(Boolean)
  if (parts.length >= 2) return { kind: 'repo', value: `${parts[0]}/${parts[1]}` }
  return { kind: 'owner', value: parts[0] }
}

function NewScan({ onCreated }) {
  const toast = useToast()
  const navigate = useNavigate()
  const meta = useMeta()
  const fileRef = useRef(null)
  const zipRef = useRef(null)
  const [mode, setMode] = useState('github')
  const [target, setTarget] = useState('')
  const [ownerType, setOwnerType] = useState('github_user')
  const [history, setHistory] = useState(true)
  const [text, setText] = useState('')
  const [label, setLabel] = useState('')
  const [file, setFile] = useState(null)
  const [repoZip, setRepoZip] = useState(null)
  const [repoHistory, setRepoHistory] = useState(true)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)

  const parsed = useMemo(() => parseTarget(target), [target])
  const tooBig = file && file.size > meta.max_upload_mb * 1024 * 1024
  const zipTooBig = repoZip && repoZip.size > meta.max_upload_mb * 1024 * 1024
  const notZip = repoZip && !/\.zip$/i.test(repoZip.name)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    try {
      let scan
      if (mode === 'github') {
        const target_type = parsed.kind === 'repo' ? 'github_repo' : ownerType
        scan = await api('/api/scans/github', { method: 'POST', body: { target_type, target: parsed.value, include_history: history } })
        navigate(`/app/scans/${scan.id}?history=${history ? 1 : 0}`)
      } else if (mode === 'local') {
        const q = new URLSearchParams({ name: repoZip.name, label, history: repoHistory ? 'true' : 'false' })
        scan = await api(`/api/scans/local?${q}`, { method: 'POST', blob: repoZip })
        navigate(`/app/scans/${scan.id}`)
      } else if (mode === 'text') {
        scan = await api('/api/scans/text', { method: 'POST', body: { content: text, label: label || 'Pasted text' } })
        navigate(`/app/scans/${scan.id}`)
      } else {
        const form = new FormData()
        form.append('file', file)
        form.append('label', label)
        scan = await api('/api/scans/upload', { method: 'POST', form })
        navigate(`/app/scans/${scan.id}`)
      }
      onCreated(scan)
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  const canSubmit = mode === 'github' ? Boolean(parsed.value) : mode === 'local' ? repoZip && !zipTooBig && !notZip
    : mode === 'text' ? text.trim().length > 0 : file && !tooBig

  return (
    <Glass className="p-5 sm:p-6">
      <Segmented value={mode} onChange={setMode} options={[
        { value: 'github', label: 'GitHub', icon: Github },
        { value: 'local', label: 'Local', icon: HardDrive },
        { value: 'text', label: 'Paste', icon: ClipboardPaste },
        { value: 'upload', label: 'File', icon: Upload },
      ]} />

      <form onSubmit={submit} className="mt-5 space-y-4">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div key={mode} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }} transition={{ duration: 0.18 }} className="space-y-4">
            {mode === 'github' && (
              <>
                <Field label="Repository, user or organization">
                  <div className="relative">
                    <Github className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-label-3" />
                    <input className="field pl-12 text-callout" autoFocus autoCapitalize="off" autoCorrect="off" spellCheck={false}
                      value={target} onChange={(e) => setTarget(e.target.value)} placeholder="github.com/owner/repo or a username" />
                  </div>
                </Field>
                <AnimatePresence initial={false}>
                  {parsed.kind && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={spring} className="overflow-hidden">
                      {parsed.kind === 'repo' ? (
                        <p className="flex items-center gap-2 px-1 text-subhead text-label-2">
                          <FolderGit2 className="h-4 w-4 text-ios-indigo" /> Repository <span className="font-mono text-label">{parsed.value}</span>
                        </p>
                      ) : (
                        <div className="space-y-2">
                          <p className="px-1 text-subhead text-label-2">Scan every public repository of <span className="font-mono text-label">{parsed.value}</span>. Is that a…</p>
                          <Segmented size="sm" value={ownerType} onChange={setOwnerType} options={[
                            { value: 'github_user', label: 'Person', icon: UserIcon },
                            { value: 'github_org', label: 'Organization', icon: Building2 },
                          ]} />
                        </div>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
                <div className="flex items-center gap-3 rounded-3xl bg-white/[0.05] px-4 py-3">
                  <History className="h-5 w-5 shrink-0 text-ios-teal" />
                  <div className="min-w-0 flex-1">
                    <div className="text-callout text-label">Check commit history</div>
                    <div className="text-footnote text-label-3">Finds secrets that were deleted but are still public</div>
                  </div>
                  <Switch checked={history} onChange={setHistory} label="Check commit history" />
                </div>
              </>
            )}

            {mode === 'local' && (
              <>
                <button type="button" onClick={() => zipRef.current?.click()}
                  onDragOver={(e) => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)}
                  onDrop={(e) => { e.preventDefault(); setDragging(false); setRepoZip(e.dataTransfer.files[0]) }}
                  className={clsx('flex w-full flex-col items-center justify-center gap-2 rounded-group border-2 border-dashed px-6 py-9 text-center transition-colors',
                    dragging ? 'border-tint bg-tint/10' : 'border-white/15 hover:border-white/30 hover:bg-white/[0.03]')}>
                  <FolderGit2 className="h-9 w-9 text-tint-light" />
                  <span className="text-headline text-label">{repoZip ? repoZip.name : 'Drop your project .zip here'}</span>
                  <span className={clsx('text-footnote', zipTooBig || notZip ? 'text-ios-red' : 'text-label-3')}>
                    {repoZip ? (notZip ? 'Choose a .zip file' : `${(repoZip.size / 1024 / 1024).toFixed(2)} MB${zipTooBig ? ` · over the ${meta.max_upload_mb} MB limit` : ''}`)
                      : `Zip the project folder, including the hidden .git folder, up to ${meta.max_upload_mb} MB`}
                  </span>
                </button>
                <input ref={zipRef} type="file" accept=".zip,application/zip" className="hidden" onChange={(e) => setRepoZip(e.target.files[0])} />
                <div className="flex items-center gap-3 rounded-3xl bg-white/[0.05] px-4 py-3">
                  <History className="h-5 w-5 shrink-0 text-ios-teal" />
                  <div className="min-w-0 flex-1">
                    <div className="text-callout text-label">Check commit history</div>
                    <div className="text-footnote text-label-3">Reads every branch from the .git folder, finds secrets deleted but still committed</div>
                  </div>
                  <Switch checked={repoHistory} onChange={setRepoHistory} label="Check commit history" />
                </div>
                <p className="flex items-start gap-2 px-1 text-footnote text-label-3">
                  <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  Scanned in memory and thrown away: the zip is never written to disk or stored. Only masked findings are saved.
                  Tip: delete node_modules first to keep the zip small (it is skipped anyway).
                </p>
              </>
            )}

            {mode === 'text' && (
              <>
                <Field label="Contents" hint="Paste code, a .env or config file, logs or a paste-site dump. Only masked findings are kept.">
                  <textarea className="field min-h-[180px] resize-y text-footnote" value={text} onChange={(e) => setText(e.target.value)}
                    placeholder={'DATABASE_URL=postgres://…\nSTRIPE_KEY=sk_live_…'} />
                </Field>
                <Field label="Name (optional)">
                  <input className="field" value={label} onChange={(e) => setLabel(e.target.value)} placeholder=".env.production" />
                </Field>
              </>
            )}

            {mode === 'upload' && (
              <>
                <button type="button" onClick={() => fileRef.current?.click()}
                  onDragOver={(e) => { e.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)}
                  onDrop={(e) => { e.preventDefault(); setDragging(false); setFile(e.dataTransfer.files[0]) }}
                  className={clsx('flex w-full flex-col items-center justify-center gap-2 rounded-group border-2 border-dashed px-6 py-10 text-center transition-colors',
                    dragging ? 'border-tint bg-tint/10' : 'border-white/15 hover:border-white/30 hover:bg-white/[0.03]')}>
                  <FileArchive className="h-9 w-9 text-tint-light" />
                  <span className="text-headline text-label">{file ? file.name : 'Choose a file or drop it here'}</span>
                  <span className={clsx('text-footnote', tooBig ? 'text-ios-red' : 'text-label-3')}>
                    {file ? `${(file.size / 1024 / 1024).toFixed(2)} MB${tooBig ? ` · over the ${meta.max_upload_mb} MB limit` : ''}`
                      : `A single file or a .zip of a project, up to ${meta.max_upload_mb} MB`}
                  </span>
                </button>
                <input ref={fileRef} type="file" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
              </>
            )}
          </motion.div>
        </AnimatePresence>

        <Button type="submit" size="lg" loading={busy} disabled={!canSubmit} className="w-full">
          {!busy && <Radar className="h-5 w-5" />} {busy ? 'Starting…' : 'Scan'}
        </Button>
        {mode === 'github' && meta.scan_time_limit_seconds && (
          <p className="text-center text-footnote text-label-3">Large organizations are scanned for up to {Math.round(meta.scan_time_limit_seconds / 60)} minutes.</p>
        )}
      </form>
    </Glass>
  )
}

export default function Scans() {
  const toast = useToast()
  const confirm = useConfirm()
  const [scans, setScans] = useState(null)

  useEffect(() => {
    let alive = true
    let timer
    const load = () => api('/api/scans?limit=100')
      .then((s) => {
        if (!alive) return
        setScans(s)
        // Poll only while something is in progress.
        if (s.some((x) => x.status === 'running' || x.status === 'queued')) timer = setTimeout(load, 3000)
      })
      .catch((e) => toast(e.message, 'error'))
    load()
    return () => { alive = false; clearTimeout(timer) }
  }, [toast])

  async function remove(scan) {
    const ok = await confirm({ title: 'Delete this scan?', message: `${scan.target} and its findings will be removed.`, confirmLabel: 'Delete', destructive: true })
    if (!ok) return
    try {
      await api(`/api/scans/${scan.id}`, { method: 'DELETE' })
      setScans((s) => s.filter((x) => x.id !== scan.id))
      toast('Scan deleted')
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  return (
    <>
      <PageHeader title="Scan" description="Check a GitHub repository, account or organization, a local repository zip, pasted text, or a file for exposed credentials." />
      <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,420px)_1fr]">
        <NewScan onCreated={(s) => setScans((x) => [s, ...(x || [])])} />
        <Group header="History">
          {!scans ? <div className="space-y-2 p-4"><div className="skeleton h-12" /><div className="skeleton h-12" /><div className="skeleton h-12" /></div>
            : scans.length === 0 ? <EmptyState icon={Radar} color="#BDBDBD" title="No scans yet">Your scans will show up here.</EmptyState>
              : (
                <ul className="divide-y divide-sep/60">
                  <AnimatePresence initial={false}>
                    {scans.map((s) => (
                      <motion.li key={s.id} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, height: 0 }} transition={spring}
                        className="group flex items-center gap-3 px-4 py-3 hover:bg-white/[0.04]">
                        <Link to={`/app/scans/${s.id}`} className="flex min-w-0 flex-1 items-center gap-3">
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-body text-label">{s.target}</div>
                            <div className="truncate text-footnote text-label-3">{TARGET_LABELS[s.target_type]}{s.monitor_id ? ' · scheduled' : ''} · {timeAgo(s.created_at)}</div>
                            {s.status === 'running' && (
                              <div className="mt-1.5 h-1 w-32 overflow-hidden rounded-full bg-fill-3"><div className="h-full rounded-full bg-tint transition-all duration-500" style={{ width: `${s.progress}%` }} /></div>
                            )}
                          </div>
                          <div className="flex shrink-0 flex-col items-end gap-1">
                            <StatusBadge status={s.status} />
                            {s.status === 'completed' && <span className="text-caption text-label-3">{plural(s.findings_count, 'finding')}</span>}
                          </div>
                          <div className="hidden sm:block">{s.status === 'completed' && <RiskMeter value={s.max_risk} />}</div>
                        </Link>
                        <button onClick={() => remove(s)} disabled={s.status === 'running'} aria-label="Delete scan" title="Delete scan"
                          className="press rounded-full p-2 text-label-4 transition-colors hover:bg-ios-red/15 hover:text-ios-red disabled:opacity-30 sm:opacity-0 sm:group-hover:opacity-100 sm:focus:opacity-100">
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </motion.li>
                    ))}
                  </AnimatePresence>
                </ul>
              )}
        </Group>
      </div>
    </>
  )
}
