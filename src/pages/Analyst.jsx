import { useEffect, useState } from 'react'
import clsx from 'clsx'
import { motion } from 'motion/react'
import {
  AlertTriangle, ExternalLink, FileWarning, GitPullRequest, KeyRound, RefreshCw, ShieldCheck, Target, ThumbsUp, Trash2, TrendingUp,
} from 'lucide-react'
import { api } from '../lib/api'
import { useMeta } from '../lib/meta'
import { plural, timeAgo } from '../lib/format'
import { Button, EmptyState, Glass, Group, PageHeader, Row, SEV_COLOR, SeverityBadge, Spinner, riskColor, spring } from '../components/ui'
import { AIFooter, Bullets, CodeBlock, Pill } from '../components/AIPanel'
import { useConfirm, useToast } from '../components/Toast'
import { GroqBadge, GroqBolt, GROQ_ORANGE } from '../components/Groq'

const GRADE_COLOR = { A: '#3DDC84', B: '#5CC8FF', C: '#F2D95C', D: '#FFA726', F: '#FF5A52' }
const VERDICT = {
  approve: ['Looks safe to merge', '#3DDC84'],
  comment: ['Merge with care', '#F2D95C'],
  request_changes: ['Changes needed', '#FF5A52'],
}
const EFFORT = { low: 'Quick win', medium: 'Some work', high: 'Bigger project' }

function ErrorLine({ children }) {
  if (!children) return null
  return <p className="mt-3 flex items-start gap-2 rounded-2xl bg-ios-red/10 px-3 py-2 text-footnote text-label"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ios-red" />{children}</p>
}

function ScoreRing({ score, grade }) {
  const c = GRADE_COLOR[grade] || '#fff'
  const r = 42
  const len = 2 * Math.PI * r
  return (
    <div className="relative h-28 w-28 shrink-0">
      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
        <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
        <motion.circle cx="50" cy="50" r={r} fill="none" stroke={c} strokeWidth="8" strokeLinecap="round" strokeDasharray={len}
          initial={{ strokeDashoffset: len }} animate={{ strokeDashoffset: len * (1 - score / 100) }} transition={{ duration: 0.9, ease: [0.32, 0.72, 0, 1] }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[34px] font-bold leading-none" style={{ color: c }}>{grade}</span>
        <span className="mt-1 text-caption tabular-nums text-label-2">{score}/100</span>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ posture */

function Posture() {
  const toast = useToast()
  const [data, setData] = useState(undefined)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => { api('/api/ai/posture').then(setData).catch(() => setData(null)) }, [])

  async function generate() {
    setBusy(true); setError(null)
    try { setData(await api('/api/ai/posture', { method: 'POST' })) } catch (e) { setError(e.message); if (e.status === 429) toast(e.message, 'error') } finally { setBusy(false) }
  }

  if (data === undefined) return <div className="skeleton h-56 rounded-group" />
  const r = data?.result
  return (
    <Glass className="p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-title3 text-label"><ShieldCheck className="h-5 w-5" /> Security posture</h2>
          <p className="mt-0.5 text-footnote text-label-3">
            {data ? <>Updated {timeAgo(data.created_at)}{data.stale && ' · your data has changed since'}</> : 'An executive summary of every scan, finding and breach check in your workspace.'}
          </p>
        </div>
        <Button size="sm" variant={data && !data.stale ? 'gray' : 'filled'} onClick={generate} loading={busy}>
          {!busy && (data ? <RefreshCw className="h-4 w-4" /> : <GroqBolt className="h-4 w-4 text-[#F43E01]" />)}{data ? 'Refresh' : 'Summarise'}
        </Button>
      </div>
      <ErrorLine>{error}</ErrorLine>
      {busy && !r && <div className="flex items-center gap-3 py-8 text-subhead text-label-2"><Spinner /> Reading your workspace statistics…</div>}
      {r && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className={clsx('mt-5', busy && 'opacity-50')}>
          <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
            <ScoreRing score={r.score} grade={r.grade} />
            <div className="min-w-0">
              <p className="text-title3 text-label">{r.headline}</p>
              <p className="mt-1.5 text-subhead text-label-2">{r.summary}</p>
              {r.trend && <p className="mt-2 flex items-center gap-1.5 text-footnote text-label-2"><TrendingUp className="h-3.5 w-3.5" /> {r.trend}</p>}
            </div>
          </div>
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <div>
              <div className="field-label">Top risks</div>
              <div className="space-y-2">
                {r.top_risks.map((t, i) => (
                  <div key={i} className="rounded-3xl bg-white/[0.05] p-3.5">
                    <div className="flex items-center justify-between gap-2"><span className="text-subhead font-semibold text-label">{t.title}</span><SeverityBadge severity={t.severity} /></div>
                    <p className="mt-1 text-footnote text-label-2">{t.detail}</p>
                  </div>
                ))}
                {!r.top_risks.length && <p className="text-subhead text-label-3">Nothing urgent.</p>}
              </div>
            </div>
            <div>
              <div className="field-label">Do next</div>
              <ol className="space-y-2">
                {r.priorities.map((p, i) => (
                  <li key={i} className="flex gap-3 rounded-3xl bg-white/[0.05] p-3.5">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white text-caption font-bold text-black">{i + 1}</span>
                    <div className="min-w-0">
                      <div className="text-subhead font-semibold text-label">{p.action}</div>
                      <p className="text-footnote text-label-2">{p.impact}</p>
                      <span className="mt-1 inline-block text-caption text-label-3">{EFFORT[p.effort] || p.effort}</span>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
          {r.wins?.length > 0 && <div className="mt-4"><div className="field-label">Going well</div><Bullets items={r.wins} color="bg-ios-green" /></div>}
          <AIFooter data={data} />
        </motion.div>
      )}
    </Glass>
  )
}

/* ------------------------------------------------------------------ pull-request review */

function Review({ review, onDelete }) {
  const r = review.result
  const [label, color] = VERDICT[r.verdict] || VERDICT.comment
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <Glass className="mt-4 overflow-hidden">
        <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center" style={{ background: `color-mix(in srgb, ${color} 9%, transparent)` }}>
          <div className="flex h-14 w-14 shrink-0 flex-col items-center justify-center rounded-[18px] bg-black/40">
            <span className="text-title3 tabular-nums" style={{ color: riskColor(r.risk_score) }}>{r.risk_score}</span>
            <span className="text-[10px] uppercase tracking-wide text-label-3">risk</span>
          </div>
          <div className="min-w-0 flex-1">
            <Pill color={color}>{label}</Pill>
            <div className="mt-1.5 truncate text-headline text-label">{review.title || `Pull request #${review.number}`}</div>
            <div className="truncate font-mono text-footnote text-label-2">{review.repo}#{review.number}{review.author ? ` · ${review.author}` : ''}</div>
          </div>
          <div className="flex gap-2">
            <Button as="a" href={review.url} target="_blank" rel="noreferrer" size="sm" variant="gray"><ExternalLink className="h-4 w-4" /> GitHub</Button>
            {onDelete && <Button size="sm" variant="plain" onClick={() => onDelete(review)} aria-label="Delete review"><Trash2 className="h-4 w-4" /></Button>}
          </div>
        </div>
        <div className="space-y-5 p-5">
          <p className="text-body text-label">{r.summary}</p>
          {review.detected_secrets?.length > 0 && (
            <div>
              <div className="field-label">Secrets GhostTrace found in this diff</div>
              <div className="space-y-1.5">
                {review.detected_secrets.map((s, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-2xl bg-ios-red/10 px-3 py-2">
                    <KeyRound className="h-4 w-4 shrink-0 text-ios-red" />
                    <div className="min-w-0 flex-1">
                      <div className="text-subhead text-label">{s.credential_type}</div>
                      <div className="truncate font-mono text-caption text-label-2">{s.file}{s.line ? `:${s.line}` : ''} · {s.masked}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div>
            <div className="field-label">{r.issues.length ? plural(r.issues.length, 'issue') : 'Issues'}</div>
            {r.issues.length === 0 && <p className="text-subhead text-label-2">No security issues found in the reviewed changes.</p>}
            <div className="space-y-3">
              {r.issues.map((it, i) => (
                <div key={i} className="rounded-3xl bg-white/[0.05] p-4" style={{ boxShadow: `inset 3px 0 0 ${SEV_COLOR[it.severity]}` }}>
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={it.severity} />
                    <span className="rounded-full bg-fill-3 px-2 py-[2px] text-caption capitalize text-label-2">{it.category.replace('_', ' ')}</span>
                    <span className="truncate font-mono text-caption text-label-3">{it.file}{it.line ? `:${it.line}` : ''}</span>
                  </div>
                  <div className="mt-2 text-subhead font-semibold text-label">{it.title}</div>
                  <p className="mt-1 text-subhead text-label-2">{it.explanation}</p>
                  <p className="mt-2 text-subhead text-label"><span className="text-label-3">Fix: </span>{it.recommendation}</p>
                  {it.suggested_fix && <div className="mt-2"><CodeBlock code={it.suggested_fix} label="Suggested change" /></div>}
                </div>
              ))}
            </div>
          </div>
          {r.good_practices?.length > 0 && (
            <div><div className="field-label flex items-center gap-1.5"><ThumbsUp className="h-3.5 w-3.5" /> Good practices</div><Bullets items={r.good_practices} color="bg-ios-green" /></div>
          )}
          {review.stats && (
            <p className="text-caption text-label-3">
              Reviewed {plural(review.stats.reviewed_files ?? 0, 'file')}
              {review.stats.skipped_files ? ` · skipped ${review.stats.skipped_files} (lockfiles, binaries, vendored)` : ''}
              {review.stats.omitted_files ? ` · ${review.stats.omitted_files} not shown (diff too large)` : ''}
            </p>
          )}
          <AIFooter data={review} />
        </div>
      </Glass>
    </motion.div>
  )
}

function PRReviews() {
  const toast = useToast()
  const confirm = useConfirm()
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [current, setCurrent] = useState(null)
  const [history, setHistory] = useState([])

  const load = () => api('/api/ai/pr-reviews').then(setHistory).catch(() => {})
  useEffect(() => { load() }, [])

  async function submit(e, refresh = false) {
    e?.preventDefault()
    if (!url.trim()) return
    setBusy(true); setError(null)
    try {
      const r = await api('/api/ai/pr-reviews', { method: 'POST', body: { url: url.trim(), refresh } })
      setCurrent(r); load()
      if (r.cached) toast('Showing the saved review for this commit')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function open(id) {
    try { setCurrent(await api(`/api/ai/pr-reviews/${id}`)) } catch (e) { toast(e.message, 'error') }
  }

  async function remove(review) {
    if (!(await confirm({ title: 'Delete this review?', confirmLabel: 'Delete', destructive: true }))) return
    try {
      await api(`/api/ai/pr-reviews/${review.id}`, { method: 'DELETE' })
      if (current?.id === review.id) setCurrent(null)
      load(); toast('Review deleted')
    } catch (e) { toast(e.message, 'error') }
  }

  return (
    <section>
      <Glass className="p-5">
        <h2 className="flex items-center gap-2 text-title3 text-label"><GitPullRequest className="h-5 w-5" /> Pull-request security review</h2>
        <p className="mt-0.5 text-footnote text-label-3">Paste a GitHub pull request. GhostTrace scans the diff for secrets, redacts them, then the AI reviews it for injection, auth, crypto and config problems.</p>
        <form onSubmit={submit} className="mt-4 flex flex-col gap-2 sm:flex-row">
          <input className="field flex-1" value={url} onChange={(e) => setUrl(e.target.value)} maxLength={300} required
            placeholder="https://github.com/owner/repo/pull/123  or  owner/repo#123" aria-label="Pull request URL" />
          <Button type="submit" loading={busy}>{!busy && <GroqBolt className="h-4 w-4 text-[#F43E01]" />} Review</Button>
        </form>
        <ErrorLine>{error}</ErrorLine>
        {busy && <div className="mt-4 flex items-center gap-3 text-subhead text-label-2"><Spinner /> Fetching the diff and reviewing it. Large PRs take up to a minute.</div>}
      </Glass>

      {current && <Review review={current} onDelete={remove} />}
      {current && (
        <div className="mt-2 flex justify-end">
          <Button size="sm" variant="plain" onClick={() => { setUrl(current.url); submit(null, true) }} disabled={busy}><RefreshCw className="h-4 w-4" /> Review again</Button>
        </div>
      )}

      {history.length > 0 && (
        <Group header="Recent reviews" className="mt-6" inset={60}>
          {history.map((h) => {
            const [label, color] = VERDICT[h.verdict] || VERDICT.comment
            return (
              <Row key={h.id} icon={h.secrets ? FileWarning : GitPullRequest} iconColor={color} onClick={() => open(h.id)} chevron
                title={h.title || `${h.repo}#${h.number}`}
                subtitle={`${h.repo}#${h.number} · ${label} · ${plural(h.issues, 'issue')}${h.secrets ? ` · ${plural(h.secrets, 'secret')}` : ''} · ${timeAgo(h.created_at)}`} />
            )
          })}
        </Group>
      )}
    </section>
  )
}

/* ------------------------------------------------------------------ page */

export default function Analyst() {
  const meta = useMeta()
  return (
    <div>
      <PageHeader title={<span className="flex flex-wrap items-center gap-3">AI Analyst <GroqBadge className="mt-1" markClassName="h-5 md:h-6" /></span>} description="Posture summaries and pull-request reviews from an AI security analyst. Secrets are redacted on the server before anything is sent." />
      {meta.ai_enabled === false ? (
        <Glass>
          <EmptyState icon={GroqBolt} color={GROQ_ORANGE} title="The AI analyst is off">
            Whoever runs this server can turn it on by adding GROQ_API_KEY to the environment (a free key from console.groq.com works).
            Explanations, fix plans and code patches then appear on every finding too.
          </EmptyState>
        </Glass>
      ) : (
        <div className="space-y-8">
          <Posture />
          <PRReviews />
          <p className="flex items-center justify-center gap-1.5 pb-2 text-center text-caption text-label-3"><Target className="h-3.5 w-3.5" /> Open any finding for an AI explanation, fix plan and code patch.</p>
        </div>
      )}
    </div>
  )
}
