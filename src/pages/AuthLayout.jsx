import { Link } from 'react-router-dom'
import { motion } from 'motion/react'
import { GhostMark } from '../components/Logo'

export default function AuthLayout({ title, subtitle, children, footer }) {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center px-4 py-12">
      <motion.div initial={{ opacity: 0, y: 24, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: 'spring', stiffness: 260, damping: 28 }} className="w-full max-w-[400px]">
        <div className="mb-7 flex flex-col items-center text-center">
          <Link to="/" aria-label="GhostTrace home" className="rounded-[22px]">
            <GhostMark className="h-[72px] w-[72px] drop-shadow-[0_12px_30px_rgba(255,255,255,0.15)]" />
          </Link>
          <h1 className="mt-5 text-title1 text-label">{title}</h1>
          {subtitle && <p className="mt-1.5 text-callout text-label-2">{subtitle}</p>}
        </div>
        <div className="glass rounded-sheet p-6 sm:p-7">{children}</div>
        {footer && <div className="mt-6 text-center text-subhead text-label-2">{footer}</div>}
      </motion.div>
    </div>
  )
}
