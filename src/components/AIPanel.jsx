import { useEffect, useState } from 'react'
import { AlertTriangle, Check, Clock, Code2, Copy, Lightbulb, RefreshCw, ShieldCheck, Wrench } from 'lucide-react'
import clsx from 'clsx'
import { Button, Segmented, Spinner } from './ui'
import { api } from '../lib/api'
import { useMeta } from '../lib/meta'
import { useToast } from './Toast'
import { GroqBadge, GroqBolt } from './Groq'

const KINDS = [
  { value: 'explain', label: 'Explain', icon: Lightbulb },
  { value: 'remediate', label: 'Fix plan', icon: Wrench },
  { value: 'patch', label: 'Code patch', icon: Code2 },
]
const BLURB = {
  explain: 'What this credential is, how an attacker could use it, and whether it looks real.',
  remediate: 'A step-by-step plan to revoke, replace and verify, with real console steps and commands.',
  patch: 'A rewrite of the code that loads the secret from the environment instead of hard-coding it.',
}
const VERDICT = {
  likely_real: ['Likely a real secret', '#FF5A52'],
  uncertain: ['Unclear if real', '#F2D95C'],
  likely_false_positive: ['Probably not a real secret', '#3DDC84'],
}
const URGENCY = { immediate: ['Act now', '#FF5A52'], soon: ['Soon', '#FFA726'], low: ['Low urgency', '#5CC8FF'] }

export function Pill({ color, children }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-[3px] text-caption font-semibold"
      style={{ color, background: `color-mix(in srgb, ${color} 16%, transparent)` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />{children}
    </span>
  )
}

export function CodeBlock({ code, label }) {
  const toast = useToast()
  return (
    <div className="overflow-hidden rounded-3xl bg-black/50">
      <div className="flex items-center justify-between px-4 pt-2.5 text-caption text-label-3">
        <span>{label}</span>
        <button className="press rounded-full p-1.5 hover:bg-white/10 hover:text-label" aria-label={`Copy ${label || 'code'}`} title="Copy"
          onClick={() => { navigator.clipboard?.writeText(code); toast('Copied') }}><Copy className="h-3.5 w-3.5" /></button>
      </div>
      <pre className="thin-scroll overflow-x-auto px-4 pb-4 pt-1 font-mono text-footnote text-label-2">{code}</pre>
    </div>
  )
}

export function Bullets({ items, color = 'bg-label-3' }) {
  if (!items?.length) return null
  return (
    <ul className="space-y-1.5">
      {items.map((t, i) => <li key={i} className="flex gap-2.5 text-subhead text-label-2"><span className={clsx('mt-[9px] h-1 w-1 shrink-0 rounded-full', color)} />{t}</li>)}
    </ul>
  )
}

function Sub({ children }) {
  return <h4 className="mb-1.5 mt-4 text-footnote font-semibold uppercase tracking-wide text-label-3">{children}</h4>
}

function Explain({ r }) {
  const [vLabel, vColor] = VERDICT[r.verdict] || VERDICT.uncertain
  const [uLabel, uColor] = URGENCY[r.urgency] || URGENCY.soon
  return (
    <div>
      <div className="flex flex-wrap gap-2"><Pill color={vColor}>{vLabel}</Pill><Pill color={uColor}>{uLabel}</Pill></div>
      <p className="mt-3 text-body text-label">{r.summary}</p>
      <Sub>What it is</Sub><p className="text-subhead text-label-2">{r.what_it_is}</p>
      <Sub>Why it matters</Sub><p className="text-subhead text-label-2">{r.why_it_matters}</p>
      <Sub>How an attacker could use it</Sub><Bullets items={r.attack_scenarios} color="bg-ios-red" />
      <Sub>Blast radius</Sub><p className="text-subhead text-label-2">{r.blast_radius}</p>
      <Sub>Is it real?</Sub><p className="text-subhead text-label-2">{r.verdict_reasoning}</p>
    </div>
  )
}

function Remediate({ r }) {
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        {r.estimated_minutes > 0 && <span className="inline-flex items-center gap-1.5 text-footnote text-label-2"><Clock className="h-3.5 w-3.5" /> About {r.estimated_minutes} min</span>}
      </div>
      <p className="mt-2 text-body text-label">{r.summary}</p>
      <ol className="mt-3 space-y-3">
        {(r.steps || []).map((s, i) => (
          <li key={i} className="flex gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/10 text-caption font-semibold text-label">{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="text-subhead font-semibold text-label">{s.title}</div>
              <p className="text-subhead text-label-2">{s.detail}</p>
              {s.command && <div className="mt-2"><CodeBlock code={s.command} label="Command" /></div>}
            </div>
          </li>
        ))}
      </ol>
      <Sub>Prevent it next time</Sub><Bullets items={r.prevention} color="bg-ios-green" />
      <Sub>Check the fix</Sub><Bullets items={r.verify} />
    </div>
  )
}

function Patch({ r }) {
  return (
    <div className="space-y-3">
      <p className="text-body text-label">{r.summary}</p>
      {r.original && <CodeBlock code={r.original} label={`Before · ${r.language || 'code'}`} />}
      {r.patched && <CodeBlock code={r.patched} label={`After · ${r.language || 'code'}`} />}
      <Bullets items={r.explanation} />
      {r.env_vars?.length > 0 && (
        <div>
          <Sub>Environment variables to set</Sub>
          <div className="space-y-1.5">
            {r.env_vars.map((v) => (
              <div key={v.name} className="rounded-2xl bg-white/[0.05] px-3 py-2">
                <code className="font-mono text-footnote text-ios-teal">{v.name}</code>
                <p className="text-footnote text-label-2">{v.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {r.gitignore_additions?.length > 0 && <CodeBlock code={r.gitignore_additions.join('\n')} label="Add to .gitignore" />}
      {r.notes?.length > 0 && <><Sub>Notes</Sub><Bullets items={r.notes} /></>}
      <p className="text-footnote text-label-3">Review and test the patch before you commit it. Rotate the old secret either way: it is still in git history.</p>
    </div>
  )
}

const VIEWS = { explain: Explain, remediate: Remediate, patch: Patch }

export function AIFooter({ data }) {
  if (!data) return null
  return (
    <p className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-label-3">
      <span className="inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" /> Secrets redacted before analysis</span>
      <span>{data.model}</span>
      {data.cached && <span>Saved answer</span>}
      <span>AI can be wrong: check before acting.</span>
    </p>
  )
}

/** AI Security Analyst section inside the finding sheet. Render with key={finding.id} so state resets per finding. */
export default function AIPanel({ finding }) {
  const meta = useMeta()
  const toast = useToast()
  const [kind, setKind] = useState('explain')
  const [answers, setAnswers] = useState({})
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)
  const id = finding?.id

  useEffect(() => {
    if (!id || !meta.ai_enabled) return
    let live = true
    api(`/api/ai/findings/${id}/insights`).then((a) => live && setAnswers(a)).catch(() => {})
    return () => { live = false }
  }, [id, meta.ai_enabled])

  async function run(refresh = false) {
    setBusy(kind); setError(null)
    try {
      const data = await api(`/api/ai/findings/${id}/${kind}`, { method: 'POST', body: { refresh } })
      setAnswers((a) => ({ ...a, [kind]: data }))
    } catch (e) {
      setError(e.message)
      if (e.status === 429) toast(e.message, 'error')
    } finally {
      setBusy(null)
    }
  }

  if (meta.ai_enabled === undefined) return null
  if (!meta.ai_enabled) {
    return (
      <section className="rounded-3xl bg-white/[0.05] p-4">
        <h3 className="flex items-center gap-2.5 text-headline text-label"><GroqBadge className="-ml-2" /> AI Security Analyst</h3>
        <p className="mt-1.5 text-subhead text-label-2">Not turned on for this server. Add <code className="font-mono text-ios-teal">GROQ_API_KEY</code> to the environment to get explanations, fix plans and code patches.</p>
      </section>
    )
  }

  const data = answers[kind]
  const View = VIEWS[kind]
  return (
    <section className="rounded-3xl bg-gradient-to-b from-white/[0.09] to-white/[0.03] p-4 ring-1 ring-inset ring-white/10">
      <div className="flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2.5 text-headline text-label"><GroqBadge className="-ml-2" /> AI Security Analyst</h3>
        {data && (
          <button onClick={() => run(true)} disabled={Boolean(busy)} className="press inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-footnote text-label-2 hover:bg-white/10 hover:text-label disabled:opacity-40">
            <RefreshCw className={clsx('h-3.5 w-3.5', busy && 'animate-spin')} /> Regenerate
          </button>
        )}
      </div>
      <Segmented className="mt-3" size="sm" options={KINDS.map((k) => ({ ...k, label: <>{k.label}{answers[k.value] && <Check className="h-3 w-3 text-ios-green" />}</> }))} value={kind} onChange={(v) => { setKind(v); setError(null) }} />
      <div className="mt-4">
        {busy === kind ? (
          <div className="flex items-center gap-3 py-6 text-subhead text-label-2"><Spinner /> Analysing with secrets redacted…</div>
        ) : data ? (
          <><View r={data.result} /><AIFooter data={data} /></>
        ) : (
          <div className="py-2">
            <p className="text-subhead text-label-2">{BLURB[kind]}</p>
            <Button className="mt-3" size="sm" onClick={() => run(false)}><GroqBolt className="h-4 w-4 text-[#F43E01]" /> Generate</Button>
          </div>
        )}
        {error && (
          <p className="mt-3 flex items-start gap-2 rounded-2xl bg-ios-red/10 px-3 py-2 text-footnote text-label"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ios-red" />{error}</p>
        )}
      </div>
    </section>
  )
}
