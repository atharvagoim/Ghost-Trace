import { Suspense, useEffect, useState } from 'react'
import { NavLink, useLocation, useNavigate, useOutlet } from 'react-router-dom'
import clsx from 'clsx'
import { AnimatePresence, motion } from 'motion/react'
import { Bell, Ellipsis, House, LogOut, MailWarning, Radar, Settings, ShieldAlert, Eye, Plus } from 'lucide-react'
import { GroqBolt, GROQ_ORANGE } from './Groq'
import Logo from './Logo'
import { PageLoader, Row, Sheet, spring } from './ui'
import { useAuth } from '../lib/auth'
import { useConfirm } from './Toast'

// Primary destinations (the first four are phone tabs); Alerts and Settings live one level down (sidebar footer / "More" on phones).
const PRIMARY = [
  { to: '/app', label: 'Home', icon: House, end: true, color: '#FFFFFF' },
  { to: '/app/scans', label: 'Scan', icon: Radar, color: '#BDBDBD' },
  { to: '/app/findings', label: 'Findings', icon: ShieldAlert, color: '#FFFFFF' },
  { to: '/app/breach', label: 'Breaches', icon: MailWarning, color: '#D4D4D4' },
  { to: '/app/monitors', label: 'Monitoring', icon: Eye, color: '#EDEDED' },
  { to: '/app/analyst', label: 'AI Analyst', icon: GroqBolt, color: GROQ_ORANGE },
]
const SECONDARY = [
  { to: '/app/alerts', label: 'Alerts', icon: Bell, color: '#F2F2F2' },
  { to: '/app/settings', label: 'Settings', icon: Settings, color: '#8E8E93' },
]
const ALL = [...PRIMARY, ...SECONDARY]

function isActive(item, pathname) {
  return item.end ? pathname === item.to : pathname.startsWith(item.to)
}

function Avatar({ user, className = 'h-9 w-9 text-subhead' }) {
  return (
    <span className={clsx('flex shrink-0 items-center justify-center rounded-full bg-gradient-to-b from-[#8E8E93] to-[#3A3A3A] font-semibold text-white', className)}>
      {(user?.full_name || user?.email || '?').charAt(0).toUpperCase()}
    </span>
  )
}

function Sidebar() {
  const { user, logout } = useAuth()
  const confirm = useConfirm()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const link = (item) => {
    const active = isActive(item, pathname)
    const Icon = item.icon
    return (
      <NavLink key={item.to} to={item.to} end={item.end}
        className={clsx('relative flex h-10 items-center gap-3 rounded-[16px] px-3 text-callout transition-colors',
          active ? 'text-white' : 'text-label-2 hover:bg-white/5 hover:text-label')}>
        {active && <motion.span layoutId="side-active" transition={spring} className="absolute inset-0 rounded-[16px] bg-white/[0.12]" />}
        <Icon className="relative h-[19px] w-[19px]" strokeWidth={2} style={{ color: active ? '#fff' : item.color }} />
        <span className="relative">{item.label}</span>
      </NavLink>
    )
  }
  return (
    <div className="glass flex h-full flex-col rounded-sheet p-3">
      <div className="px-2 pb-5 pt-2"><Logo to="/app" /></div>
      <button onClick={() => navigate('/app/scans')}
        className="press mb-4 flex h-10 items-center justify-center gap-2 rounded-[16px] bg-white/10 text-callout font-semibold text-label hover:bg-white/15">
        <Plus className="h-4 w-4" strokeWidth={2.5} /> New scan
      </button>
      <nav className="space-y-0.5">{PRIMARY.map(link)}</nav>
      <div className="mt-5 px-3 pb-1 text-footnote text-label-3">Account</div>
      <nav className="space-y-0.5">{SECONDARY.map(link)}</nav>
      <div className="mt-auto flex items-center gap-3 rounded-3xl bg-white/[0.04] p-2.5">
        <Avatar user={user} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-subhead font-medium text-label">{user?.full_name || 'Your account'}</div>
          <div className="truncate text-caption text-label-3">{user?.email}</div>
        </div>
        <button onClick={async () => { if (await confirm({ title: 'Sign out?', confirmLabel: 'Sign out', destructive: true })) logout() }}
          className="press rounded-full p-2 text-label-3 hover:bg-white/10 hover:text-label" aria-label="Sign out" title="Sign out">
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

function TabBar({ onMore }) {
  const { pathname } = useLocation()
  const tabs = PRIMARY.slice(0, 4)
  const moreActive = !tabs.some((t) => isActive(t, pathname))
  return (
    <nav className="glass-bar hairline-t fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 pb-[max(6px,env(safe-area-inset-bottom))] pt-1.5 lg:hidden">
      {tabs.map((t) => {
        const active = isActive(t, pathname)
        const Icon = t.icon
        return (
          <NavLink key={t.to} to={t.to} end={t.end} className={clsx('press flex flex-col items-center gap-0.5 py-1 text-caption2 font-medium', active ? 'text-tint-light' : 'text-label-3')}>
            <Icon className="h-6 w-6" strokeWidth={active ? 2.3 : 1.8} />
            {t.label}
          </NavLink>
        )
      })}
      <button onClick={onMore} className={clsx('press flex flex-col items-center gap-0.5 py-1 text-caption2 font-medium', moreActive ? 'text-tint-light' : 'text-label-3')}>
        <Ellipsis className="h-6 w-6" strokeWidth={moreActive ? 2.3 : 1.8} />
        More
      </button>
    </nav>
  )
}

/** Compact title that fades in once the page's large title has scrolled under the bar (phones). */
function TopBar() {
  const { pathname } = useLocation()
  const [show, setShow] = useState(false)
  const current = ALL.find((n) => isActive(n, pathname))
  useEffect(() => {
    const onScroll = () => setShow(window.scrollY > 56)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [pathname])
  return (
    <header className={clsx('fixed inset-x-0 top-0 z-30 flex h-[calc(44px+env(safe-area-inset-top))] items-end justify-center pb-2.5 transition-all duration-300 ease-ios lg:hidden',
      show ? 'glass-bar hairline-b' : 'bg-transparent')}>
      <span className={clsx('text-headline text-label transition-opacity duration-200', show ? 'opacity-100' : 'opacity-0')}>{current?.label || 'GhostTrace'}</span>
    </header>
  )
}

// Keeps the outgoing page on screen during its exit animation (a live <Outlet/> would already show the next page).
function FrozenOutlet() {
  const outlet = useOutlet()
  const [frozen] = useState(outlet)
  return frozen
}

export default function AppLayout() {
  const [more, setMore] = useState(false)
  const location = useLocation()
  const { user, logout } = useAuth()
  const confirm = useConfirm()

  useEffect(() => { window.scrollTo({ top: 0 }) }, [location.pathname])

  return (
    <div className="min-h-dvh">
      <aside className="fixed inset-y-3 left-3 z-30 hidden w-[264px] lg:block"><Sidebar /></aside>
      <TopBar />

      <div className="lg:pl-[280px]">
        <main className="mx-auto max-w-6xl px-4 pb-32 pt-[calc(52px+env(safe-area-inset-top))] sm:px-6 lg:px-10 lg:pb-16 lg:pt-10">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div key={location.pathname}
              initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.22, ease: [0.32, 0.72, 0, 1] }}>
              <Suspense fallback={<PageLoader />}><FrozenOutlet /></Suspense>
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <TabBar onMore={() => setMore(true)} />
      <Sheet open={more} onClose={() => setMore(false)} title="More">
        <div className="mb-5 flex items-center gap-3 px-1">
          <Avatar user={user} className="h-12 w-12 text-title3" />
          <div className="min-w-0">
            <div className="truncate text-headline text-label">{user?.full_name || 'Your account'}</div>
            <div className="truncate text-subhead text-label-2">{user?.email}</div>
          </div>
        </div>
        <div className="space-y-6">
          <div className="glass overflow-hidden rounded-group">
            {[...PRIMARY.slice(4), ...SECONDARY].map((n) => (
              <div key={n.to} onClick={() => setMore(false)}><Row icon={n.icon} iconColor={n.color} title={n.label} to={n.to} /></div>
            ))}
          </div>
          <div className="glass overflow-hidden rounded-group">
            <Row title="Sign out" titleClassName="text-ios-red" onClick={async () => {
              if (await confirm({ title: 'Sign out?', confirmLabel: 'Sign out', destructive: true })) { setMore(false); logout() }
            }} />
          </div>
        </div>
      </Sheet>
    </div>
  )
}
