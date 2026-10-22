import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import AuthLayout from './AuthLayout'
import { Button, Field } from '../components/ui'
import { api } from '../lib/api'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const navigate = useNavigate()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setError('')
    if (password !== confirm) return setError('Passwords do not match.')
    setLoading(true)
    try {
      await api('/api/auth/reset-password', { method: 'POST', body: { token, password } })
      setDone(true)
      setTimeout(() => navigate('/login', { replace: true }), 2000)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout
      title="Choose a new password"
      subtitle="Use at least 8 characters."
      footer={<Link to="/login" className="font-medium text-tint-light hover:underline">Back to sign in</Link>}
    >
      {!token ? (
        <div role="alert" className="rounded-3xl bg-ios-red/15 px-4 py-3 text-subhead text-ios-red">
          This reset link is incomplete. <Link to="/forgot-password" className="underline">Request a new one</Link>.
        </div>
      ) : done ? (
        <div role="status" className="rounded-3xl bg-ios-green/15 px-4 py-3 text-subhead text-label">
          Password updated. Taking you to sign in…
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-5">
          <Field label="New password">
            <input className="field" type="password" autoComplete="new-password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <Field label="Confirm new password">
            <input className="field" type="password" autoComplete="new-password" required minLength={8} value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </Field>
          {error && (
            <div role="alert" className="rounded-3xl bg-ios-red/15 px-4 py-3 text-subhead text-ios-red">
              {error} {error.includes('expired') && <Link to="/forgot-password" className="underline">Request a new link</Link>}
            </div>
          )}
          <Button type="submit" loading={loading} size="lg" className="w-full">Update password</Button>
        </form>
      )}
    </AuthLayout>
  )
}
