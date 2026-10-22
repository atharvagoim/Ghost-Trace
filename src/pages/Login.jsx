import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import AuthLayout from './AuthLayout'
import { Button, Field } from '../components/ui'
import { useAuth } from '../lib/auth'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(email, password)
      navigate(location.state?.from || '/app', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout
      title="Sign in to GhostTrace"
      subtitle="Welcome back."
      footer={<>New to GhostTrace? <Link to="/register" className="font-medium text-tint-light hover:underline">Create an account</Link></>}
    >
      <form onSubmit={submit} className="space-y-5">
        <Field label="Email">
          <input className="field" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Password">
          <input className="field" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <div className="-mt-3 text-right">
          <Link to="/forgot-password" className="text-subhead text-tint-light hover:underline">Forgot password?</Link>
        </div>
        {error && <div role="alert" className="rounded-3xl bg-ios-red/15 px-4 py-3 text-subhead text-ios-red">{error}</div>}
        <Button type="submit" loading={loading} size="lg" className="w-full">Sign in</Button>
      </form>
    </AuthLayout>
  )
}
