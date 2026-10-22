import { motion } from 'motion/react'

/** Activity-style concentric rings: each ring is one severity, filled by its share of all open findings.
 *  An empty dashboard shows three faint closed tracks, which reads as "all clear". */
export default function ExposureRings({ critical = 0, high = 0, medium = 0, size = 200 }) {
  const total = Math.max(critical + high + medium, 1)
  const rings = [
    { value: critical, color: '#FF5A52', glow: '#FF8A84' },
    { value: high, color: '#FFA726', glow: '#FFC266' },
    { value: medium, color: '#F2D95C', glow: '#F7E78F' },
  ]
  const stroke = size * 0.105
  const gap = stroke * 0.22
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0 -rotate-90" aria-hidden="true">
      {rings.map((r, i) => {
        const radius = size / 2 - stroke / 2 - i * (stroke + gap)
        const c = 2 * Math.PI * radius
        const frac = r.value ? Math.max(0.04, r.value / total) : 0
        return (
          <g key={i}>
            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={r.color} strokeOpacity={0.2} strokeWidth={stroke} />
            <motion.circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={`url(#ring-${i})`} strokeWidth={stroke}
              strokeLinecap="round" strokeDasharray={c}
              initial={{ strokeDashoffset: c }} animate={{ strokeDashoffset: c * (1 - frac) }}
              transition={{ type: 'spring', stiffness: 50, damping: 16, delay: 0.15 + i * 0.12 }} />
            <defs>
              <linearGradient id={`ring-${i}`} x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stopColor={r.glow} /><stop offset="1" stopColor={r.color} />
              </linearGradient>
            </defs>
          </g>
        )
      })}
    </svg>
  )
}
