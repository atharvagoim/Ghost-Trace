import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import AuthLayout from './AuthLayout'
import { Button, Field } from '../components/ui'
import { useAuth } from '../lib/auth'

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ full_name: '', organization: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  async function submit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await register(form)
      navigate('/app', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout
      title="Create your account"
      subtitle="Free, and your first scan takes about a minute."
      footer={<>Already have an account? <Link to="/login" className="font-medium text-tint-light hover:underline">Sign in</Link></>}
    >
      <form onSubmit={submit} className="space-y-5">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input className="field" autoComplete="name" value={form.full_name} onChange={set('full_name')} />
          </Field>
          <Field label="Organization">
            <input className="field" autoComplete="organization" value={form.organization} onChange={set('organization')} />
          </Field>
        </div>
        <Field label="Email">
          <input className="field" type="email" autoComplete="email" required value={form.email} onChange={set('email')} />
        </Field>
        <Field label="Password" hint="At least 8 characters.">
          <input className="field" type="password" autoComplete="new-password" minLength={8} required value={form.password} onChange={set('password')} />
        </Field>
        {error && <div role="alert" className="rounded-3xl bg-ios-red/15 px-4 py-3 text-subhead text-ios-red">{error}</div>}
        <Button type="submit" loading={loading} size="lg" className="w-full">Create account</Button>
      </form>
    </AuthLayout>
  )
}
