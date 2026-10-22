import { useState } from 'react'
import { Link } from 'react-router-dom'
import AuthLayout from './AuthLayout'
import { Button, Field } from '../components/ui'
import { api } from '../lib/api'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await api('/api/auth/forgot-password', { method: 'POST', body: { email } })
      setSent(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout
      title="Forgot your password?"
      subtitle="Enter your email and we'll send you a link to choose a new one."
      footer={<>Remembered it? <Link to="/login" className="font-medium text-tint-light hover:underline">Back to sign in</Link></>}
    >
      {sent ? (
        <div role="status" className="rounded-3xl bg-ios-green/15 px-4 py-3 text-subhead text-label">
          If an account exists for <b>{email}</b>, a reset link is on its way. It is valid for 30 minutes.
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-5">
          <Field label="Email">
            <input className="field" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          {error && <div role="alert" className="rounded-3xl bg-ios-red/15 px-4 py-3 text-subhead text-ios-red">{error}</div>}
          <Button type="submit" loading={loading} size="lg" className="w-full">Send reset link</Button>
        </form>
      )}
    </AuthLayout>
  )
}
