import { useEffect, useState } from 'react'
import clsx from 'clsx'
import { AnimatePresence, motion } from 'motion/react'
import { Bell, CheckCircle2, Eye, EyeOff, KeyRound, Lock, Mail, MailSearch, ShieldAlert } from 'lucide-react'
import { api } from '../lib/api'
import { nf, timeAgo } from '../lib/format'
import { Button, Glass, Group, PageHeader, Row, Segmented, spring } from '../components/ui'
import { useToast } from '../components/Toast'

const SENSITIVE = /password|credit|bank|social|auth/i

function EmailResult({ result, onMonitor }) {
  const clean = result.breach_count === 0
  return (
    <motion.div key={result.email + result.checked_at} initial={{ opacity: 0, y: 16, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={spring}>
      <Glass className="mt-4 overflow-hidden">
        <div className={clsx('flex flex-col gap-4 p-5 sm:flex-row sm:items-center', clean ? 'bg-ios-green/10' : 'bg-ios-red/10')}>
          {clean ? <CheckCircle2 className="h-11 w-11 shrink-0 text-ios-green" /> : <ShieldAlert className="h-11 w-11 shrink-0 text-ios-red" />}
          <div className="min-w-0 flex-1">
            <div className="text-title2 text-label">{clean ? 'No known breaches' : `Found in ${result.breach_count} breach${result.breach_count === 1 ? '' : 'es'}`}</div>
            <div className="truncate font-mono text-subhead text-label-2">{result.email}</div>
          </div>
          <Button variant="gray" size="sm" onClick={() => onMonitor(result.email)}><Bell className="h-3.5 w-3.5" /> Alert me about new breaches</Button>
        </div>
        {!clean && (
          <div className="p-5">
            {result.exposed_data.length > 0 && (
              <>
                <div className="field-label">What was exposed</div>
                <div className="mb-5 flex flex-wrap gap-2">
                  {result.exposed_data.map((d) => (
                    <span key={d} className={clsx('rounded-full px-3 py-1 text-footnote font-medium', SENSITIVE.test(d) ? 'bg-ios-red/15 text-ios-red' : 'bg-fill-3 text-label-2')}>{d}</span>
                  ))}
                </div>
              </>
            )}
            <ul className="divide-y divide-sep/60">
              {result.breaches.map((b) => (
                <li key={b.name + b.date} className="flex gap-3.5 py-3.5">
                  <div className="flex h-11 w-11 shrink-0 items-center justify-center overflow-hidden rounded-[12px] bg-white">
                    {b.logo ? <img src={b.logo} alt="" className="h-full w-full object-contain p-1" onError={(e) => { e.currentTarget.style.display = 'none' }} /> : <MailSearch className="h-5 w-5 text-black/60" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                      <span className="text-headline text-label">{b.name}</span>
                      <span className="text-footnote text-label-3">{b.date}{b.records ? ` · ${nf.format(b.records)} accounts` : ''}</span>
                    </div>
                    {b.description && <p className="mt-1 line-clamp-2 text-subhead text-label-2">{b.description}</p>}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Glass>
    </motion.div>
  )
}

const STRENGTH = [['Very weak', '#FF5A52'], ['Weak', '#FFA726'], ['Fair', '#F2D95C'], ['Strong', '#5CC8FF'], ['Very strong', '#3DDC84']]

function PasswordCheck() {
  const toast = useToast()
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [pw, setPw] = useState(null)
  const [busy, setBusy] = useState(false)
  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    try { setPw(await api('/api/breach/password', { method: 'POST', body: { password } })) } catch (err) { toast(err.message, 'error') } finally { setBusy(false) }
  }
  return (
    <Glass className="p-5 sm:p-6">
      <form onSubmit={submit} className="space-y-4">
        <div className="relative">
          <KeyRound className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-label-3" />
          <input className="field pl-12 pr-12" type={show ? 'text' : 'password'} required value={password} autoComplete="off"
            onChange={(e) => { setPassword(e.target.value); setPw(null) }} placeholder="Type a password to check" />
          <button type="button" onClick={() => setShow((s) => !s)} className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-1.5 text-label-3 hover:text-label" aria-label={show ? 'Hide password' : 'Show password'}>
            {show ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
          </button>
        </div>
        <Button type="submit" size="lg" loading={busy} disabled={!password} className="w-full">{!busy && <Lock className="h-5 w-5" />} Check password</Button>
      </form>
      <AnimatePresence>
        {pw && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} transition={spring} className="overflow-hidden">
            <div className="mt-5 space-y-3">
              <div className="flex gap-1.5">
                {[0, 1, 2, 3, 4].map((i) => (
                  <motion.div key={i} className="h-1.5 flex-1 rounded-full" initial={{ background: 'rgba(118,118,128,0.24)' }}
                    animate={{ background: i <= pw.strength ? STRENGTH[pw.strength][1] : 'rgba(118,118,128,0.24)' }} transition={{ delay: i * 0.06 }} />
                ))}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-headline" style={{ color: STRENGTH[pw.strength][1] }}>{pw.strength_label || STRENGTH[pw.strength][0]}</span>
                <span className={clsx('text-subhead font-medium', pw.pwned ? 'text-ios-red' : 'text-ios-green')}>
                  {pw.pwned ? `Seen ${nf.format(pw.count)} times in leaks` : 'Not found in known leaks'}
                </span>
              </div>
              {pw.feedback.length > 0 && (
                <ul className="space-y-1.5 text-subhead text-label-2">
                  {pw.feedback.map((f) => <li key={f} className="flex gap-2.5"><span className="mt-[9px] h-1 w-1 shrink-0 rounded-full bg-label-3" />{f}</li>)}
                </ul>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      <p className="mt-5 text-footnote text-label-3">
        Your password never leaves this server: only the first 5 characters of its SHA-1 hash are sent to Pwned Passwords, and nothing is stored.
      </p>
    </Glass>
  )
}

export default function Breach() {
  const toast = useToast()
  const [tab, setTab] = useState('email')
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])

  useEffect(() => { api('/api/breach/history').then(setHistory).catch(() => {}) }, [])

  async function checkEmail(e) {
    e.preventDefault()
    setBusy(true)
    try {
      const r = await api('/api/breach/email', { method: 'POST', body: { email } })
      setResult(r)
      setHistory((h) => [r, ...h.filter((x) => x.email !== r.email)])
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function monitor(addr) {
    try {
      await api('/api/monitors', { method: 'POST', body: { target_type: 'email', target: addr } })
      toast(`You’ll be alerted if ${addr} shows up in a new breach`)
    } catch (err) {
      toast(err.message, 'error')
    }
  }

  return (
    <>
      <PageHeader title="Breaches" description="See whether an email address or password has shown up in a known data breach." />
      <Segmented className="mb-5 max-w-sm" value={tab} onChange={setTab}
        options={[{ value: 'email', label: 'Email', icon: Mail }, { value: 'password', label: 'Password', icon: KeyRound }]} />

      {tab === 'email' ? (
        <div className="grid items-start gap-8 xl:grid-cols-[1fr_340px]">
          <div>
            <Glass className="p-5 sm:p-6">
              <form onSubmit={checkEmail} className="flex flex-col gap-3 sm:flex-row">
                <div className="relative flex-1">
                  <Mail className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-label-3" />
                  <input className="field pl-12" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.com" />
                </div>
                <Button type="submit" size="lg" loading={busy}>{!busy && <MailSearch className="h-5 w-5" />} Check</Button>
              </form>
            </Glass>
            <AnimatePresence mode="wait">{result && <EmailResult result={result} onMonitor={monitor} />}</AnimatePresence>
          </div>
          <Group header="Recently checked">
            {history.length === 0 ? <Row title="Nothing checked yet" className="text-label-2" /> : history.slice(0, 12).map((h) => (
              <Row key={h.id} onClick={() => setResult(h)} title={<span className="font-mono text-callout">{h.email}</span>} subtitle={timeAgo(h.checked_at)}
                detail={<span className={clsx('text-subhead font-medium', h.breach_count ? 'text-ios-red' : 'text-ios-green')}>{h.breach_count ? `${h.breach_count} breaches` : 'Clean'}</span>} />
            ))}
          </Group>
        </div>
      ) : (
        <div className="max-w-xl"><PasswordCheck /></div>
      )}
    </>
  )
}
