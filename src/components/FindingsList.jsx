import { ChevronRight, GitCommit } from 'lucide-react'
import { motion } from 'motion/react'
import { RiskMeter, SeverityBadge, StatusBadge } from './ui'
import { timeAgo } from '../lib/format'

/** Findings as an iOS list: severity tick on the left, what & where in the middle, risk on the right. */
export default function FindingsList({ items, onSelect, compact = false }) {
  return (
    <ul className="divide-y divide-sep/60">
      {items.map((f, i) => (
        <motion.li key={f.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i, 12) * 0.025, duration: 0.25 }}>
          <button type="button" onClick={() => onSelect?.(f)}
            className="group flex w-full items-center gap-3.5 px-6 py-3.5 text-left transition-colors hover:bg-white/[0.04] active:bg-white/10">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-body font-medium text-label">{f.credential_type}</span>
                {!compact && <span className="hidden sm:inline"><SeverityBadge severity={f.severity} /></span>}
              </div>
              <div className="mt-0.5 flex min-w-0 items-center gap-2 text-footnote text-label-2">
                <span className="truncate font-mono" title={`${f.repository || ''}/${f.file_path || ''}`}>
                  {f.repository && <span className="text-label-3">{f.repository}/</span>}{f.file_path}{f.line_number ? `:${f.line_number}` : ''}
                </span>
                {f.in_history_only && (
                  <span className="hidden shrink-0 items-center gap-1 text-ios-indigo sm:inline-flex"><GitCommit className="h-3 w-3" /> history</span>
                )}
              </div>
            </div>
            {!compact && <div className="hidden w-28 md:block"><StatusBadge status={f.status} /></div>}
            {!compact && <div className="hidden w-20 text-right text-footnote text-label-3 lg:block">{timeAgo(f.first_seen)}</div>}
            <div className="shrink-0"><RiskMeter value={f.risk_score} /></div>
            <ChevronRight className="h-4 w-4 shrink-0 text-label-4 transition-transform group-hover:translate-x-0.5" strokeWidth={2.5} />
          </button>
        </motion.li>
      ))}
    </ul>
  )
}
