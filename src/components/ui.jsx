import { useEffect, useId } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { ChevronRight, X } from 'lucide-react'

export const spring = { type: 'spring', stiffness: 420, damping: 38, mass: 0.9 }
export const softSpring = { type: 'spring', stiffness: 260, damping: 30 }

/* ------------------------------------------------------------------ buttons */

const BUTTON_VARIANTS = {
  filled: 'bg-white text-black hover:bg-[#e6e6e6] active:bg-[#d4d4d4]',
  tinted: 'bg-[#2c2c2c] text-white hover:bg-[#383838] active:bg-[#444]',
  gray: 'bg-[#1e1e1e] text-white hover:bg-[#2a2a2a] active:bg-[#363636]',
  plain: 'bg-transparent text-label-2 hover:bg-[#1e1e1e] hover:text-white',
  destructive: 'bg-[#2b1513] text-[#FF5A52] hover:bg-[#3a1c19] active:bg-[#47221e]',
}
// Sizes sit within 4px of each other: same type size, same pill shape.
const BUTTON_SIZES = {
  sm: 'h-10 px-5 text-callout font-semibold gap-2 rounded-full',
  md: 'h-11 px-6 text-callout font-semibold gap-2 rounded-full',
  lg: 'h-12 px-7 text-callout font-semibold gap-2 rounded-full',
}

export function Button({ variant = 'filled', size = 'md', loading, className, children, as: As = 'button', ...props }) {
  const isButton = As === 'button'
  return (
    <As
      className={clsx(
        'press inline-flex select-none items-center justify-center whitespace-nowrap leading-none transition-[background-color,color,box-shadow,transform] duration-200 [&>svg]:shrink-0',
        'disabled:pointer-events-none disabled:opacity-40',
        BUTTON_VARIANTS[variant], BUTTON_SIZES[size], className,
      )}
      {...(isButton ? { disabled: loading || props.disabled, type: props.type || 'button' } : {})}
      {...props}
    >
      {loading ? <Spinner className="h-4 w-4" color="currentColor" /> : null}
      {children}
    </As>
  )
}

export function IconButton({ label, className, children, ...props }) {
  return (
    <button type="button" aria-label={label} title={label}
      className={clsx('press flex h-10 w-10 items-center justify-center rounded-full bg-[#1e1e1e] text-label-2 transition-colors hover:bg-[#2a2a2a] hover:text-white', className)}
      {...props}>
      {children}
    </button>
  )
}

/* ------------------------------------------------------------------ surfaces */

export function Glass({ className, children, as: As = 'div', ...props }) {
  return <As className={clsx('glass rounded-group', className)} {...props}>{children}</As>
}

/** iOS inset grouped list section: optional header above, footer note below, rows separated by inset hairlines. */
export function Group({ header, action, footer, className, children, inset = 16 }) {
  return (
    <section className={className}>
      {(header || action) && (
        <div className="mb-2 flex items-end justify-between gap-3 px-4">
          {header && <h2 className="text-title3 text-label">{header}</h2>}
          {action}
        </div>
      )}
      <div style={{ '--sep-inset': `${inset}px` }} className="glass overflow-hidden rounded-group [&>*+*]:relative [&>*+*]:before:absolute [&>*+*]:before:left-[var(--sep-inset)] [&>*+*]:before:right-0 [&>*+*]:before:top-0 [&>*+*]:before:h-px [&>*+*]:before:scale-y-50 [&>*+*]:before:bg-sep">
        {children}
      </div>
      {footer && <p className="mt-2 px-4 text-footnote text-label-3">{footer}</p>}
    </section>
  )
}

/** Settings-style coloured square behind a white glyph. */
export function IconTile({ icon: Icon, color = '#FFFFFF', className }) {
  return (
    <span className={clsx('flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-[12px] bg-gradient-to-b from-[#1c1c1c] to-[#0a0a0a] ', className)}
      style={{ color }}>
      <Icon className="h-[17px] w-[17px]" strokeWidth={2.2} />
    </span>
  )
}

export function Row({ icon, iconColor, leading, title, subtitle, detail, trailing, chevron, onClick, to, className, titleClassName }) {
  const body = (
    <>
      {leading ?? (icon && <IconTile icon={icon} color={iconColor} />)}
      <div className="min-w-0 flex-1">
        <div className={clsx('truncate text-body text-label', titleClassName)}>{title}</div>
        {subtitle && <div className="truncate text-subhead text-label-2">{subtitle}</div>}
      </div>
      {detail != null && <div className="shrink-0 text-body text-label-2">{detail}</div>}
      {trailing}
      {(chevron || to) && <ChevronRight className="h-4 w-4 shrink-0 text-label-4" strokeWidth={2.5} />}
    </>
  )
  const cls = clsx('flex min-h-[52px] w-full items-center gap-3.5 px-4 py-2.5 text-left', (onClick || to) && 'transition-colors active:bg-white/10 hover:bg-white/[0.04]', className)
  if (to) return <Link to={to} className={cls}>{body}</Link>
  if (onClick) return <button type="button" onClick={onClick} className={cls}>{body}</button>
  return <div className={cls}>{body}</div>
}

/* ------------------------------------------------------------------ controls */

export function Segmented({ options, value, onChange, className, size = 'md' }) {
  const id = useId()
  return (
    <div role="tablist" className={clsx('relative flex rounded-[16px] bg-fill-4 p-[2px]', className)}>
      {options.map((o) => {
        const active = o.value === value
        const Icon = o.icon
        return (
          <button key={o.value} type="button" role="tab" aria-selected={active} onClick={() => onChange(o.value)}
            className={clsx('relative flex flex-[1_1_auto] items-center justify-center gap-1.5 whitespace-nowrap rounded-[12px] px-2.5 font-medium transition-colors',
              size === 'sm' ? 'h-7 text-footnote' : 'h-8 text-subhead', active ? 'text-label' : 'text-label-2 hover:text-label')}>
            {active && (
              <motion.span layoutId={`seg-${id}`} transition={spring}
                className="absolute inset-0 rounded-[12px] bg-[#3a3a3a]" />
            )}
            <span className="relative flex items-center gap-1.5">{Icon && <Icon className="h-4 w-4" />}{o.label}</span>
          </button>
        )
      })}
    </div>
  )
}

export function Switch({ checked, onChange, label, disabled }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx('relative h-[31px] w-[51px] shrink-0 rounded-full transition-colors duration-300 ease-ios disabled:opacity-40',
        checked ? 'bg-[#3DDC84]' : 'bg-fill-1')}>
      <motion.span layout transition={spring}
        className={clsx('absolute top-[2px] h-[27px] w-[27px] rounded-full shadow-[0_3px_8px_rgba(0,0,0,0.3)]', 'bg-white',
          checked ? 'right-[2px]' : 'left-[2px]')} />
    </button>
  )
}

export function Field({ label, hint, error, children, className }) {
  return (
    <label className={clsx('block', className)}>
      {label && <span className="field-label">{label}</span>}
      {children}
      {hint && !error && <span className="mt-1.5 block px-1 text-footnote text-label-3">{hint}</span>}
      {error && <span className="mt-1.5 block px-1 text-footnote text-ios-red">{error}</span>}
    </label>
  )
}

export function Notice({ tone = 'info', icon: Icon, children, className }) {
  const tones = {
    info: 'bg-tint/12 text-label ring-tint/30',
    warn: 'bg-ios-orange/12 text-label ring-ios-orange/30',
    error: 'bg-ios-red/12 text-label ring-ios-red/30',
    success: 'bg-ios-green/12 text-label ring-ios-green/30',
  }
  const iconColor = { info: 'text-tint-light', warn: 'text-ios-orange', error: 'text-ios-red', success: 'text-ios-green' }
  return (
    <div className={clsx('flex items-start gap-3 rounded-3xl px-4 py-3 text-subhead ring-1 ring-inset', tones[tone], className)}>
      {Icon && <Icon className={clsx('mt-0.5 h-[18px] w-[18px] shrink-0', iconColor[tone])} />}
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}

/* ------------------------------------------------------------------ status */

export const SEV_COLOR = { critical: '#FF5A52', high: '#FFA726', medium: '#F2D95C', low: '#5CC8FF' }
export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

export function SeverityBadge({ severity }) {
  const c = SEV_COLOR[severity] || SEV_COLOR.low
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-[3px] text-caption font-semibold"
      style={{ color: c, background: `color-mix(in srgb, ${c} 16%, transparent)` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
      {SEV_LABEL[severity] || severity}
    </span>
  )
}

const STATUS = {
  completed: ['Done', '#3DDC84'],
  running: ['Scanning', '#5CC8FF'],
  queued: ['Starting', 'rgba(235,235,245,0.6)'],
  failed: ['Failed', '#FF5A52'],
  open: ['Open', '#FFA726'],
  resolved: ['Rotated', '#3DDC84'],
  false_positive: ['Not a secret', 'rgba(235,235,245,0.6)'],
  sent: ['Sent', '#3DDC84'],
  skipped: ['Not sent', 'rgba(235,235,245,0.6)'],
}

export function StatusBadge({ status }) {
  const [label, color] = STATUS[status] || [String(status).replace('_', ' '), 'rgba(235,235,245,0.6)']
  if (status === 'open') {
    // "Open" is the call to action in findings lists, so it is a solid white pill.
    return (
      <span className="inline-flex h-7 items-center gap-1.5 rounded-full bg-white px-3 text-footnote font-semibold leading-none text-black">
        <span className="h-[6px] w-[6px] rounded-full bg-[#3DDC84]" />
        {label}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-footnote font-medium" style={{ color }}>
      <span className={clsx('h-[7px] w-[7px] rounded-full', (status === 'running' || status === 'queued') && 'animate-pulseDot')} style={{ background: color }} />
      {label}
    </span>
  )
}

export function riskColor(v) {
  return v >= 75 ? SEV_COLOR.critical : v >= 55 ? SEV_COLOR.high : v >= 30 ? SEV_COLOR.medium : SEV_COLOR.low
}

export function RiskMeter({ value, wide }) {
  const v = Math.round(value || 0)
  const color = riskColor(v)
  return (
    <div className="flex items-center gap-2">
      <div className={clsx('h-[5px] overflow-hidden rounded-full bg-fill-3', wide ? 'w-full' : 'w-14')}>
        <motion.div className="h-full rounded-full" style={{ background: color }}
          initial={{ width: 0 }} animate={{ width: `${v}%` }} transition={softSpring} />
      </div>
      <span className="w-6 text-right font-mono text-footnote tabular-nums text-label-2">{v}</span>
    </div>
  )
}

/** iOS activity indicator: twelve fading spokes. */
export function Spinner({ className = 'h-5 w-5', color = 'rgba(235,235,245,0.7)' }) {
  return (
    <svg viewBox="0 0 24 24" className={clsx('animate-spin [animation-duration:0.9s] [animation-timing-function:steps(12)]', className)} aria-label="Loading" role="status">
      {Array.from({ length: 12 }, (_, i) => (
        <rect key={i} x="11" y="2" width="2" height="6" rx="1" fill={color} opacity={0.15 + (i / 12) * 0.85}
          transform={`rotate(${i * 30} 12 12)`} />
      ))}
    </svg>
  )
}

export function PageLoader() {
  return (
    <div className="space-y-4 pt-2" aria-busy="true">
      <div className="skeleton h-10 w-56" />
      <div className="grid gap-4 sm:grid-cols-3">
        <div className="skeleton h-28 rounded-group" /><div className="skeleton h-28 rounded-group" /><div className="skeleton h-28 rounded-group" />
      </div>
      <div className="skeleton h-64 rounded-group" />
    </div>
  )
}

export function EmptyState({ icon: Icon, title, children, action, color = '#FFFFFF' }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {Icon && (
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-[20px]" style={{ background: `color-mix(in srgb, ${color} 18%, transparent)` }}>
          <Icon className="h-8 w-8" style={{ color }} />
        </div>
      )}
      <h3 className="text-title3 text-label">{title}</h3>
      {children && <p className="mt-1.5 max-w-sm text-subhead text-label-2">{children}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  )
}

/* ------------------------------------------------------------------ page chrome */

/** iOS large title. The compact title in the top bar (AppLayout) takes over once this scrolls away. */
export function PageHeader({ title, description, actions, back, center }) {
  return (
    <header className={clsx('mb-7', center && 'text-center')}>
      {back}
      <div className={clsx('flex flex-col gap-4', !center && 'md:flex-row md:items-end md:justify-between')}>
        <div className="min-w-0">
          <h1 data-large-title className="text-large-title text-label md:text-[40px] md:leading-[46px]">{title}</h1>
          {description && <p className={clsx('mt-1.5 max-w-2xl text-callout text-label-2', center && 'mx-auto')}>{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
      </div>
    </header>
  )
}

/* ------------------------------------------------------------------ sheet */

/** Bottom sheet on phones (drag down to close), floating side panel on larger screens. */
export function Sheet({ open, onClose, title, children, footer, wide }) {
  const reduce = useReducedMotion()
  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { window.removeEventListener('keydown', onKey); document.body.style.overflow = prev }
  }, [open, onClose])

  const desktop = typeof window !== 'undefined' && window.matchMedia('(min-width: 768px)').matches
  const from = reduce ? { opacity: 0 } : desktop ? { x: 40, opacity: 0 } : { y: '100%' }
  const to = reduce ? { opacity: 1 } : desktop ? { x: 0, opacity: 1 } : { y: 0 }

  // Portalled to <body> so no page transform/opacity can trap it under the tab bar or break its backdrop blur.
  return createPortal(
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : undefined}>
          <motion.div className="absolute inset-0 bg-black/50" onClick={onClose}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.25 }} />
          <motion.aside
            className={clsx('glass-thick absolute flex flex-col overflow-hidden',
              'inset-x-0 bottom-0 max-h-[92dvh] rounded-t-sheet pb-[env(safe-area-inset-bottom)]',
              'md:inset-y-3 md:left-auto md:right-3 md:max-h-none md:rounded-sheet md:pb-0', wide ? 'md:w-[min(760px,calc(100vw-24px))]' : 'md:w-[480px]')}
            initial={from} animate={to} exit={from} transition={spring}
            drag={!desktop && !reduce ? 'y' : false} dragConstraints={{ top: 0, bottom: 0 }} dragElastic={{ top: 0, bottom: 0.6 }}
            onDragEnd={(_, info) => { if (info.offset.y > 120 || info.velocity.y > 600) onClose() }}
          >
            <div className="flex justify-center pt-2 md:hidden"><span className="h-[5px] w-9 rounded-full bg-label-4" /></div>
            <div className="flex items-center justify-between gap-3 px-5 pb-2 pt-3 md:pt-5">
              <div className="min-w-0 text-headline text-label">{title}</div>
              <IconButton label="Close" onClick={onClose}><X className="h-4 w-4" strokeWidth={2.5} /></IconButton>
            </div>
            <div className="thin-scroll flex-1 overflow-y-auto px-5 pb-6 pt-2">{children}</div>
            {footer && <div className="hairline-t flex flex-wrap gap-2 px-5 py-4">{footer}</div>}
          </motion.aside>
        </div>
      )}
    </AnimatePresence>,
    document.body,
  )
}
