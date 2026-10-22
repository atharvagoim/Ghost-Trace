import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { motion } from 'motion/react'
import { AlertTriangle, ChevronLeft, FileDown, FileSpreadsheet, RotateCw, ShieldCheck } from 'lucide-react'
import { api, download } from '../lib/api'
import { formatDate, plural, TARGET_LABELS } from '../lib/format'
import { Button, EmptyState, Glass, Group, Notice, PageHeader, PageLoader, SEV_COLOR, StatusBadge } from '../components/ui'
import FindingsList from '../components/FindingsList'
import FindingDrawer from '../components/FindingDrawer'
import { useToast } from '../components/Toast'

function Progress({ scan }) {
  return (
    <Glass className="relative mb-8 overflow-hidden p-6">
      <motion.div aria-hidden="true" className="pointer-events-none absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-white/[0.07] to-transparent"
        animate={{ x: ['-100%', '300%'] }} transition={{ duration: 2.2, repeat: Infinity, ease: 'linear' }} />
      <div className="relative">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <StatusBadge status={scan.status} />
            <p className="mt-1 truncate text-callout text-label">{scan.message || 'Starting…'}</p>
          </div>
          <span className="text-title1 tabular-nums text-label">{scan.progress}<span className="text-title3 text-label-3">%</span></span>
        </div>
        <div className="mt-5 h-2 overflow-hidden rounded-full bg-fill-3">
          <motion.div className="h-full rounded-full bg-gradient-to-r from-ios-indigo to-tint"
            animate={{ width: `${Math.max(scan.progress, 3)}%` }} transition={{ type: 'spring', stiffness: 80, damping: 20 }} />
        </div>
        <div className="mt-4 grid grid-cols-3 gap-3 text-center">
          {[['Repositories', scan.repos_scanned], ['Files', scan.files_scanned], ['Commits', scan.commits_scanned]].map(([l, v]) => (
            <div key={l} className="rounded-3xl bg-white/[0.05] py-2.5">
              <div className="text-title3 tabular-nums text-label">{v}</div>
              <div className="text-caption text-label-3">{l}</div>
            </div>
          ))}
        </div>
        <p className="mt-4 text-footnote text-label-3">You can leave this page open; results appear here as soon as the scan finishes.</p>
      </div>
    </Glass>
  )
}

export default function ScanDetail() {
  const { id } = useParams()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [rerunning, setRerunning] = useState(false)
  const started = useRef(false)

  useEffect(() => {
    let alive = true
    let timer
    started.current = false
    async function load() {
      try {
        const s = await api(`/api/scans/${id}`)
        if (!alive) return
        setScan(s)
        // A queued GitHub scan is started by this request. On Vercel it runs inside it; on a regular server a background
        // task usually got there first and this returns straight away. Either way the scan runs exactly once.
        if (s.status === 'queued' && s.target_type.startsWith('github') && !started.current) {
          started.current = true
          api(`/api/scans/${id}/run?include_history=${params.get('history') === '0' ? 'false' : 'true'}`, { method: 'POST' })
            .then((done) => alive && setScan(done)).catch(() => {})
        }
        if (s.status === 'completed' || s.status === 'failed') {
          setFindings(await api(`/api/scans/${id}/findings`))
        } else {
          timer = setTimeout(load, 1500)
        }
      } catch (e) {
        toast(e.message, 'error')
      }
    }
    load()
    return () => { alive = false; clearTimeout(timer) }
  }, [id, toast]) // eslint-disable-line react-hooks/exhaustive-deps

  async function rerun() {
    setRerunning(true)
    try {
      const s = await api('/api/scans/github', { method: 'POST', body: { target_type: scan.target_type, target: scan.target, include_history: true } })
      navigate(`/app/scans/${s.id}`)
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setRerunning(false)
    }
  }

  if (!scan) return <PageLoader />
  const running = scan.status === 'running' || scan.status === 'queued'
  const sev = findings.reduce((a, f) => ({ ...a, [f.severity]: (a[f.severity] || 0) + 1 }), {})

  return (
    <>
      <PageHeader
        back={<Link to="/app/scans" className="mb-3 -ml-1.5 inline-flex items-center text-body text-tint-light hover:underline"><ChevronLeft className="h-6 w-6" strokeWidth={2.4} />Scans</Link>}
        title={<span className="break-all">{scan.target}</span>}
        description={`${TARGET_LABELS[scan.target_type]} · ${formatDate(scan.created_at)}`}
        actions={scan.status === 'completed' && (
          <>
            <Button variant="gray" onClick={() => download(`/api/reports/findings.csv?scan_id=${scan.id}`, `ghosttrace-scan-${scan.id}.csv`).catch((e) => toast(e.message, 'error'))}>
              <FileSpreadsheet className="h-4 w-4" /> CSV
            </Button>
            <Button variant="gray" onClick={() => download(`/api/reports/scan/${scan.id}.pdf`, `ghosttrace-scan-${scan.id}.pdf`).catch((e) => toast(e.message, 'error'))}>
              <FileDown className="h-4 w-4" /> PDF
            </Button>
          </>
        )}
      />

      {running && <Progress scan={scan} />}

      {scan.status === 'failed' && (
        <Notice tone="error" icon={AlertTriangle} className="mb-8">
          <div className="font-semibold">The scan didn’t finish</div>
          <p className="mt-0.5 text-label-2">{scan.error}</p>
          {scan.target_type.startsWith('github') && (
            <Button size="sm" variant="tinted" className="mt-3" loading={rerunning} onClick={rerun}><RotateCw className="h-3.5 w-3.5" /> Try again</Button>
          )}
        </Notice>
      )}

      {scan.status === 'completed' && (
        <>
          <div className="mb-8 grid grid-cols-4 gap-2.5 sm:gap-3">
            {['critical', 'high', 'medium', 'low'].map((s, i) => (
              <motion.div key={s} initial={{ opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05, type: 'spring', stiffness: 400, damping: 28 }}>
                <Glass className="p-3 text-center sm:p-4">
                  <div className="text-title1 tabular-nums" style={{ color: sev[s] ? SEV_COLOR[s] : 'rgba(235,235,245,0.3)' }}>{sev[s] || 0}</div>
                  <div className="text-caption capitalize text-label-2 sm:text-footnote">{s}</div>
                </Glass>
              </motion.div>
            ))}
          </div>
          {scan.message && <p className="-mt-5 mb-8 px-1 text-footnote text-label-3">{scan.message}</p>}
        </>
      )}

      {!running && (findings.length > 0 || scan.status === 'completed') && (
        <Group header={findings.length ? plural(findings.length, 'finding') : undefined}>
          {findings.length ? <FindingsList items={findings} onSelect={setSelected} /> : (
            scan.status === 'completed' && (
              <EmptyState icon={ShieldCheck} color="#EDEDED" title="Nothing exposed">No credentials were found in this {TARGET_LABELS[scan.target_type].toLowerCase()}.</EmptyState>
            )
          )}
        </Group>
      )}

      <FindingDrawer finding={selected} onClose={() => setSelected(null)}
        onChange={(f) => { setSelected(f); setFindings((xs) => xs.map((x) => (x.fingerprint === f.fingerprint ? { ...x, status: f.status } : x))) }} />
    </>
  )
}
