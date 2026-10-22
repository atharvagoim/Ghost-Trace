import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import clsx from 'clsx'
import { ChevronLeft, ChevronRight, FileSpreadsheet, Search, ShieldCheck, X } from 'lucide-react'
import { api, download } from '../lib/api'
import { plural } from '../lib/format'
import { Button, EmptyState, Group, PageHeader, SEV_COLOR, Segmented } from '../components/ui'
import FindingsList from '../components/FindingsList'
import FindingDrawer from '../components/FindingDrawer'
import { useToast } from '../components/Toast'

const SEVS = ['critical', 'high', 'medium', 'low']
const CATS = [
  ['aws', 'AWS'], ['cloud', 'Cloud'], ['api_key', 'API keys'], ['token', 'Tokens'], ['jwt', 'JWT'],
  ['private_key', 'Private keys'], ['database', 'Databases'], ['password', 'Passwords'], ['email', 'Emails'], ['webhook', 'Webhooks'],
]

function Pill({ active, onClick, color, children }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active}
      className={clsx('press inline-flex h-8 shrink-0 items-center gap-1.5 rounded-full px-3.5 text-subhead font-medium transition-colors',
        active ? 'bg-white text-black' : 'bg-fill-3 text-label-2 hover:bg-fill-2 hover:text-label')}>
      {color && <span className="h-2 w-2 rounded-full" style={{ background: color }} />}
      {children}
    </button>
  )
}

export default function Findings() {
  const toast = useToast()
  const [params, setParams] = useSearchParams()
  const [data, setData] = useState(null)
  const [selected, setSelected] = useState(null)
  const [query, setQuery] = useState(params.get('q') || '')

  const filters = useMemo(() => ({
    severity: params.get('severity') || '',
    category: params.get('category') || '',
    status: params.get('status') ?? 'open',
    q: params.get('q') || '',
    sort: params.get('sort') || 'risk',
    page: Number(params.get('page') || 1),
  }), [params])

  const qs = useMemo(() => {
    const p = new URLSearchParams()
    Object.entries(filters).forEach(([k, v]) => { if (v !== '' && v !== null) p.set(k, v) })
    p.set('page_size', 25)
    return p.toString()
  }, [filters])

  useEffect(() => {
    api(`/api/findings?${qs}`).then(setData).catch((e) => toast(e.message, 'error'))
  }, [qs, toast])

  useEffect(() => {
    const t = setTimeout(() => { if (query !== filters.q) update({ q: query }) }, 300)
    return () => clearTimeout(t)
  }, [query]) // eslint-disable-line react-hooks/exhaustive-deps

  function update(patch) {
    const next = new URLSearchParams(params)
    Object.entries({ ...patch, page: patch.page ?? 1 }).forEach(([k, v]) => { if (v === '' || v === null || v === undefined) next.delete(k); else next.set(k, v) })
    if (patch.status === '') next.set('status', '')
    setParams(next, { replace: true })
  }

  function toggle(key, value) {
    const cur = filters[key] ? filters[key].split(',') : []
    const next = cur.includes(value) ? cur.filter((x) => x !== value) : [...cur, value]
    update({ [key]: next.join(',') })
  }

  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  const csvParams = new URLSearchParams(qs)
  csvParams.delete('page'); csvParams.delete('page_size'); csvParams.delete('sort')
  const filtered = filters.severity || filters.category || filters.q

  return (
    <>
      <PageHeader title="Findings" description="Every exposed credential, riskiest first. Open one to see why it scored that way and how to fix it."
        actions={<Button variant="gray" onClick={() => download(`/api/reports/findings.csv?${csvParams}`, 'ghosttrace-findings.csv').catch((e) => toast(e.message, 'error'))}><FileSpreadsheet className="h-4 w-4" /> Export CSV</Button>} />

      <div className="space-y-3">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-label-3" />
          <input className="field h-11 rounded-[12px] py-0 pl-10 pr-10" type="search" placeholder="Search repositories, files, types or people"
            value={query} onChange={(e) => setQuery(e.target.value)} />
          {query && (
            <button onClick={() => setQuery('')} aria-label="Clear search" className="absolute right-3 top-1/2 flex h-5 w-5 -translate-y-1/2 items-center justify-center rounded-full bg-label-3 text-black">
              <X className="h-3 w-3" strokeWidth={3} />
            </button>
          )}
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <Segmented className="sm:w-[440px] [&_button]:text-footnote sm:[&_button]:text-subhead" value={filters.status} onChange={(v) => update({ status: v })}
            options={[{ value: 'open', label: 'Open' }, { value: 'resolved', label: 'Rotated' }, { value: 'false_positive', label: 'Not a secret' }, { value: '', label: 'All' }]} />
          <Segmented className="sm:ml-auto sm:w-52" size="sm" value={filters.sort} onChange={(v) => update({ sort: v })}
            options={[{ value: 'risk', label: 'Riskiest' }, { value: 'newest', label: 'Newest' }]} />
        </div>
        <div className="no-scrollbar -mx-4 flex gap-2 overflow-x-auto px-4 pb-1 md:mx-0 md:flex-wrap md:overflow-visible md:px-0">
          {SEVS.map((s) => <Pill key={s} color={SEV_COLOR[s]} active={filters.severity.split(',').includes(s)} onClick={() => toggle('severity', s)}><span className="capitalize">{s}</span></Pill>)}
          <span className="mx-1 w-px shrink-0 self-stretch bg-sep md:hidden" />
          {CATS.map(([c, l]) => <Pill key={c} active={filters.category.split(',').includes(c)} onClick={() => toggle('category', c)}>{l}</Pill>)}
        </div>
      </div>

      <Group className="mt-6" header={data ? plural(data.total, 'finding') : ' '}
        action={filtered ? <button className="text-callout text-tint-light hover:underline" onClick={() => { setQuery(''); update({ severity: '', category: '', q: '' }) }}>Clear filters</button> : null}>
        {!data ? <div className="space-y-2 p-4">{[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-12" />)}</div>
          : data.items.length === 0 ? (
            <EmptyState icon={ShieldCheck} color="#EDEDED" title={filtered ? 'No matches' : filters.status === 'open' ? 'Nothing left to fix' : 'Nothing here'}>
              {filtered ? 'Try fewer filters or a different search.' : 'Run a scan to look for more.'}
            </EmptyState>
          ) : <FindingsList items={data.items} onSelect={setSelected} />}
      </Group>

      {data && pages > 1 && (
        <div className="mt-4 flex items-center justify-center gap-3 text-subhead text-label-2">
          <Button variant="gray" size="sm" disabled={filters.page <= 1} onClick={() => update({ page: filters.page - 1 })} aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></Button>
          <span>Page {filters.page} of {pages}</span>
          <Button variant="gray" size="sm" disabled={filters.page >= pages} onClick={() => update({ page: filters.page + 1 })} aria-label="Next page"><ChevronRight className="h-4 w-4" /></Button>
        </div>
      )}

      <FindingDrawer finding={selected} onClose={() => setSelected(null)}
        onChange={(f) => { setSelected(f); setData((d) => ({ ...d, items: d.items.map((x) => (x.fingerprint === f.fingerprint ? { ...x, status: f.status } : x)) })) }} />
    </>
  )
}
