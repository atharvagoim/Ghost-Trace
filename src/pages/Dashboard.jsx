import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bar } from 'react-chartjs-2'
import { motion } from 'motion/react'
import { CheckCircle2, FileDown, FolderGit2, MailWarning, Radar, ShieldCheck } from 'lucide-react'
import { Github as GithubLucide } from '../components/icons'
import { api, download } from '../lib/api'
import { SEV_COLORS, tooltip } from '../lib/charts'
import { plural, timeAgo, TARGET_LABELS } from '../lib/format'
import { Button, EmptyState, Glass, Group, PageHeader, PageLoader, Row, Segmented, StatusBadge, riskColor } from '../components/ui'
import FindingsList from '../components/FindingsList'
import FindingDrawer from '../components/FindingDrawer'
import ExposureRings from '../components/ExposureRings'
import CountUp from '../components/CountUp'
import { useAuth } from '../lib/auth'
import { useToast } from '../components/Toast'

function headline(t) {
  if (t.critical_open > 0) return `${plural(t.critical_open, 'critical leak')} ${t.critical_open === 1 ? 'needs' : 'need'} rotating now.`
  if (t.high_open > 0) return `No critical leaks. ${plural(t.high_open, 'high-risk finding')} to review.`
  if (t.open > 0) return `Nothing urgent. ${plural(t.open, 'low-risk finding')} left to tidy up.`
  return 'All clear. Nothing exposed right now.'
}

function Legend({ color, label, value }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
      <span className="text-subhead text-label-2">{label}</span>
      <span className="ml-auto text-headline tabular-nums text-label"><CountUp to={value} /></span>
    </div>
  )
}

function Widget({ label, value, hint, delay = 0 }) {
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay, type: 'spring', stiffness: 300, damping: 30 }}>
      <Glass className="h-full p-4">
        <div className="text-footnote text-label-2">{label}</div>
        <div className="mt-1 text-title1 tabular-nums text-label"><CountUp to={value} /></div>
        {hint && <div className="mt-0.5 text-footnote text-label-3">{hint}</div>}
      </Glass>
    </motion.div>
  )
}

export default function Dashboard() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()
  const [data, setData] = useState(null)
  const [days, setDays] = useState(30)
  const [selected, setSelected] = useState(null)
  const [pdfBusy, setPdfBusy] = useState(false)

  useEffect(() => {
    api(`/api/dashboard/summary?days=${days}`).then(setData).catch((e) => toast(e.message, 'error'))
  }, [days, toast])

  if (!data) return <PageLoader />
  const t = data.totals
  const firstName = user?.full_name ? user.full_name.split(' ')[0] : ''

  if (t.scans === 0 && t.findings === 0) {
    return (
      <>
        <PageHeader title={firstName ? `Hi, ${firstName}` : 'Welcome'} description="Let’s see what you have exposed. It takes about a minute." />
        <Glass className="p-2">
          <EmptyState icon={Radar} color="#BDBDBD" title="Run your first scan"
            action={<Button size="lg" onClick={() => navigate('/app/scans')}><Radar className="h-5 w-5" /> Start a scan</Button>}>
            Paste a GitHub repo, username or organization. GhostTrace checks the code and its history for passwords, keys and tokens.
          </EmptyState>
        </Glass>
      </>
    )
  }

  const trendBySev = Object.fromEntries(['critical', 'high', 'medium', 'low'].map((k) => [k, data.trend.reduce((n, d) => n + (d[k] || 0), 0)]))
  const trendTotal = Object.values(trendBySev).reduce((n, v) => n + v, 0)
  const catTotal = data.by_category.reduce((n, c) => n + c.count, 0) || 1
  const catMax = Math.max(1, ...data.by_category.map((c) => c.count))
  const trendData = {
    labels: data.trend.map((d) => new Date(d.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })),
    datasets: ['critical', 'high', 'medium', 'low'].map((k) => ({
      label: k[0].toUpperCase() + k.slice(1), data: data.trend.map((d) => d[k]), backgroundColor: SEV_COLORS[k],
      borderColor: '#121212', borderWidth: 2, borderRadius: 6, borderSkipped: false, stack: 'sev', barPercentage: 0.7, maxBarThickness: 14,
    })),
  }

  return (
    <>
      <PageHeader
        title={firstName ? `Hi, ${firstName}` : 'Home'}
        actions={
          <>
            <Button variant="gray" loading={pdfBusy} onClick={() => {
              setPdfBusy(true)
              download('/api/reports/summary.pdf', 'ghosttrace-summary.pdf').catch((e) => toast(e.message, 'error')).finally(() => setPdfBusy(false))
            }}>
              {!pdfBusy && <FileDown className="h-4 w-4" />} PDF report
            </Button>
            <Button onClick={() => navigate('/app/scans')}><Radar className="h-4 w-4" /> New scan</Button>
          </>
        }
      />

      {/* The one thing to know: rings + a sentence + the action. */}
      <Glass className="relative overflow-hidden p-6 sm:p-8">
        <div className="flex flex-col items-center gap-8 sm:flex-row sm:items-center">
          <div className="relative">
            <ExposureRings critical={t.critical_open} high={t.high_open} medium={Math.max(t.open - t.critical_open - t.high_open, 0)} size={196} />
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              {t.open === 0 ? <CheckCircle2 className="h-9 w-9 text-ios-green" /> : (
                <>
                  <span className="text-title3 font-semibold leading-none tabular-nums text-label"><CountUp to={t.open} /></span>
                  <span className="mt-0.5 text-caption2 text-label-2">open</span>
                </>
              )}
            </div>
          </div>
          <div className="w-full min-w-0 flex-1">
            <p className="text-title2 text-label sm:text-title1">{headline(t)}</p>
            <div className="mt-5 max-w-xs space-y-2.5">
              <Legend color="#FF5A52" label="Critical" value={t.critical_open} />
              <Legend color="#FFA726" label="High" value={t.high_open} />
              <Legend color="#F2D95C" label="Medium and low" value={Math.max(t.open - t.critical_open - t.high_open, 0)} />
            </div>
            {t.open > 0 && (
              <div className="mt-6 flex flex-wrap gap-2">
                <Button onClick={() => navigate(t.critical_open ? '/app/findings?severity=critical' : '/app/findings')}>
                  Review {t.critical_open ? 'critical leaks' : 'findings'}
                </Button>
                {t.resolved > 0 && <Button variant="plain" onClick={() => navigate('/app/findings?status=resolved')}>{t.resolved} fixed so far</Button>}
              </div>
            )}
          </div>
        </div>
      </Glass>

      <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Widget label="Average risk" value={Math.round(t.avg_risk)} hint="of 100, open findings" delay={0.05} />
        <Widget label="Files checked" value={t.files_scanned} hint={plural(t.repositories, 'repository', 'repositories')} delay={0.1} />
        <Widget label="Scans" value={t.scans} hint={`${t.monitors_active} on a schedule`} delay={0.15} />
        <Widget label="Breached emails" value={t.breached_emails} hint="of the ones you checked" delay={0.2} />
      </div>

      {data.top_findings.length > 0 && (
        <Group className="mt-8" header="Fix these first" action={<Link to="/app/findings" className="text-callout text-tint-light hover:underline">See all</Link>}>
          <FindingsList items={data.top_findings.slice(0, 6)} onSelect={setSelected} compact />
        </Group>
      )}

      <div className="mt-8 grid gap-6 lg:grid-cols-5">
        <Glass className="p-6 lg:col-span-3">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-footnote font-medium text-label-2">New leaks over time</h2>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-[40px] font-semibold leading-none tracking-tight tabular-nums text-label"><CountUp to={trendTotal} /></span>
                <span className="text-footnote text-label-3">in the last {days} days</span>
              </div>
            </div>
            <Segmented size="sm" className="w-44" value={days} onChange={setDays}
              options={[{ value: 14, label: '14d' }, { value: 30, label: '30d' }, { value: 90, label: '90d' }]} />
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {['critical', 'high', 'medium', 'low'].map((k) => (
              <span key={k} className="inline-flex h-7 items-center gap-2 rounded-full bg-[#1e1e1e] px-3 text-caption text-label-2">
                <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[k] }} />
                <span className="capitalize">{k}</span>
                <span className="font-semibold tabular-nums text-label">{trendBySev[k]}</span>
              </span>
            ))}
          </div>
          <div className="mt-5 h-52">
            <Bar data={trendData} options={{
              maintainAspectRatio: false,
              layout: { padding: { top: 6 } },
              plugins: { legend: { display: false }, tooltip },
              scales: {
                x: { stacked: true, grid: { display: false }, border: { display: false }, ticks: { maxTicksLimit: 6, padding: 6 } },
                y: { stacked: true, beginAtZero: true, border: { display: false }, grid: { color: 'rgba(255,255,255,0.06)', drawTicks: false }, ticks: { precision: 0, maxTicksLimit: 4, padding: 10 } },
              },
            }} />
          </div>
        </Glass>

        <Glass className="p-6 lg:col-span-2">
          <h2 className="text-footnote font-medium text-label-2">What leaked</h2>
          {data.by_category.length ? (
            <>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-[40px] font-semibold leading-none tracking-tight tabular-nums text-label"><CountUp to={catTotal} /></span>
                <span className="text-footnote text-label-3">open across {plural(data.by_category.length, 'type')}</span>
              </div>
              <ul className="mt-6 space-y-4">
                {data.by_category.slice(0, 6).map((c, i) => (
                  <li key={c.label}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="truncate text-subhead text-label">{c.label}</span>
                      <span className="shrink-0 text-subhead tabular-nums text-label-2">{c.count}<span className="ml-1.5 text-caption text-label-3">{Math.round((c.count / catTotal) * 100)}%</span></span>
                    </div>
                    <div className="mt-2 h-2 overflow-hidden rounded-full bg-[#1e1e1e]">
                      <motion.div className="h-full rounded-full bg-white" style={{ opacity: Math.max(0.35, 1 - i * 0.15) }}
                        initial={{ width: 0 }} animate={{ width: `${(c.count / catMax) * 100}%` }}
                        transition={{ type: 'spring', stiffness: 80, damping: 18, delay: 0.1 + i * 0.06 }} />
                    </div>
                  </li>
                ))}
              </ul>
            </>
          ) : <EmptyState icon={ShieldCheck} color="#EDEDED" title="Nothing open" />}
        </Glass>
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-2">
        <Group header="Most exposed repositories" inset={60}>
          {data.top_repositories.length === 0 && <Row title="No repository findings yet" className="text-label-2" />}
          {data.top_repositories.slice(0, 5).map((r) => (
            <Row key={r.repository} icon={FolderGit2} iconColor="#BDBDBD" to={`/app/findings?q=${encodeURIComponent(r.repository)}`}
              title={<span className="font-mono text-callout">{r.repository}</span>} subtitle={`${r.open} open · ${r.critical} critical`}
              detail={<span className="font-semibold tabular-nums" style={{ color: riskColor(r.max_risk) }}>{Math.round(r.max_risk)}</span>} />
          ))}
        </Group>
        <Group header="Recent scans" inset={60} action={<Link to="/app/scans" className="text-callout text-tint-light hover:underline">All scans</Link>}>
          {data.recent_scans.slice(0, 5).map((s) => (
            <Row key={s.id} icon={s.target_type.startsWith('github') ? GithubLucide : Radar} iconColor="#2A2A2A" to={`/app/scans/${s.id}`}
              title={s.target} subtitle={`${TARGET_LABELS[s.target_type]} · ${timeAgo(s.created_at)}`}
              trailing={<div className="flex flex-col items-end gap-0.5"><StatusBadge status={s.status} /><span className="text-caption text-label-3">{plural(s.findings_count, 'finding')}</span></div>} />
          ))}
        </Group>
      </div>

      {t.breached_emails === 0 && (
        <Glass className="mt-8 flex flex-col gap-4 p-5 sm:flex-row sm:items-center">
          <MailWarning className="h-8 w-8 shrink-0 text-ios-orange" />
          <div className="flex-1">
            <div className="text-headline text-label">Check your team’s email addresses</div>
            <p className="text-subhead text-label-2">See whether they appear in known data breaches, and get told when they do.</p>
          </div>
          <Button variant="tinted" onClick={() => navigate('/app/breach')}>Check an email</Button>
        </Glass>
      )}

      <FindingDrawer finding={selected} onClose={() => setSelected(null)}
        onChange={(f) => { setSelected(f); setData((d) => ({ ...d, top_findings: d.top_findings.map((x) => (x.id === f.id ? f : x)) })) }} />
    </>
  )
}
