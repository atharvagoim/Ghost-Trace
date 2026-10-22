import { Link } from 'react-router-dom'

// Plain white ghost, no tile. The eyes are cut out so whatever sits behind shows through.
export function GhostMark({ className = 'h-8 w-8' }) {
  return (
    <svg viewBox="10 10 44 44" className={className} aria-hidden="true">
      <defs>
        <mask id="gt-eyes">
          <rect x="10" y="10" width="44" height="44" fill="#fff" />
          <circle cx="26.5" cy="30" r="3.2" fill="#000" />
          <circle cx="37.5" cy="30" r="3.2" fill="#000" />
        </mask>
      </defs>
      <path d="M32 13c-9.4 0-16 6.7-16 16.2V51l5.3-3.8 5.4 3.8 5.3-3.8 5.3 3.8 5.4-3.8L48 51V29.2C48 19.7 41.4 13 32 13Z" fill="#fff" mask="url(#gt-eyes)" />
    </svg>
  )
}

export default function Logo({ to = '/', compact = false }) {
  return (
    <Link to={to} className="flex items-center gap-2.5 rounded-row">
      <GhostMark />
      {!compact && <span className="text-headline text-label">GhostTrace</span>}
    </Link>
  )
}
