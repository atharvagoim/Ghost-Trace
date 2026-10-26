import { useEffect, useState } from 'react'
import { GroqBolt, GROQ_ORANGE } from '../components/Groq'
import { Bell, CheckCircle2, Database, Mail, ShieldCheck, XCircle } from 'lucide-react'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { useMeta } from '../lib/meta'
import { Github } from '../components/icons'
import { Button, Field, Group, PageHeader, Row, Segmented, Switch } from '../components/ui'
import { useToast } from '../components/Toast'

function Check({ ok }) {
  return ok ? <CheckCircle2 className="h-5 w-5 text-ios-green" /> : <XCircle className="h-5 w-5 text-label-3" />
}

export default function Settings() {
  const { user, setUser } = useAuth()
  const toast = useToast()
  const meta = useMeta()
  const [form, setForm] = useState({
    full_name: user.full_name, organization: user.organization, alerts_enabled: user.alerts_enabled, alert_min_severity: user.alert_min_severity,
  })
  const [config, setConfig] = useState(null)
  const [busy, setBusy] = useState(false)
  const dirty = Object.keys(form).some((k) => form[k] !== user[k])

  useEffect(() => { api('/api/alerts/config').then(setConfig).catch(() => {}) }, [])

  async function save(e) {
    e?.preventDefault()
    setBusy(true)
    try {
      setUser(await api('/api/auth/me', { method: 'PATCH', body: form }))
      toast('Settings saved')
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader title="Settings" center />
      <form onSubmit={save} className="mx-auto max-w-2xl space-y-8">
        <Group header="Profile">
          <div className="grid gap-4 p-4 sm:grid-cols-2">
            <Field label="Name"><input className="field" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></Field>
            <Field label="Organization"><input className="field" value={form.organization} onChange={(e) => setForm({ ...form, organization: e.target.value })} /></Field>
          </div>
          <Row icon={Mail} iconColor="#FFFFFF" title="Email" detail={<span className="text-subhead">{user.email}</span>} />
        </Group>

        <Group header="Email alerts" inset={60} footer="Only new findings at or above this severity trigger an email.">
          <Row icon={Bell} iconColor="#F2F2F2" title="Email me about new leaks"
            trailing={<Switch checked={form.alerts_enabled} onChange={(v) => setForm({ ...form, alerts_enabled: v })} label="Email me about new leaks" />} />
          <div className={form.alerts_enabled ? 'p-4' : 'pointer-events-none p-4 opacity-40'}>
            <Segmented value={form.alert_min_severity} onChange={(v) => setForm({ ...form, alert_min_severity: v })} options={[
              { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High+' }, { value: 'medium', label: 'Medium+' }, { value: 'low', label: 'All' },
            ]} />
          </div>
        </Group>

        <div className="flex justify-center">
          <Button type="submit" loading={busy} disabled={!dirty}>Save changes</Button>
        </div>

        {config && (
          <Group header="Server" inset={60} footer="These are set by whoever runs this GhostTrace server, through environment variables.">
            <Row icon={Github} iconColor="#2A2A2A" title="GitHub access" subtitle={config.github_token_configured ? 'Up to 5,000 requests an hour' : 'No token: 60 requests an hour, small scans only'} trailing={<Check ok={config.github_token_configured} />} />
            <Row icon={Mail} iconColor="#FFFFFF" title="Email delivery" subtitle={config.email_configured ? 'Alerts are emailed' : 'Alerts are logged, not emailed'} trailing={<Check ok={config.email_configured} />} />
            <Row icon={ShieldCheck} iconColor="#D4D4D4" title="Breach data" subtitle={config.breach_source} trailing={<Check ok />} />
            <Row icon={GroqBolt} iconColor={GROQ_ORANGE} title="AI Security Analyst" subtitle={config.ai_configured ? `Groq · ${config.ai_model}` : 'Off: set GROQ_API_KEY to turn it on'} trailing={<Check ok={config.ai_configured} />} />
            <Row icon={Database} iconColor="#EDEDED" title="Storage" subtitle={meta.persistent_storage ? 'Saved in MongoDB' : 'In-memory: data is lost on restart. Set MONGODB_URI.'} trailing={<Check ok={meta.persistent_storage} />} />
          </Group>
        )}
      </form>
    </>
  )
}
