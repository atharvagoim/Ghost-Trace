import { Link } from 'react-router-dom'
import { GhostMark } from '../components/Logo'
import { Button } from '../components/ui'

export default function NotFound() {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center px-6 text-center">
      <GhostMark className="h-20 w-20 opacity-90" />
      <h1 className="mt-6 text-title1 text-label">This page doesn’t exist</h1>
      <p className="mt-2 text-callout text-label-2">The link may be old, or the address mistyped.</p>
      <Button as={Link} to="/" size="lg" className="mt-8">Go to GhostTrace</Button>
    </div>
  )
}
