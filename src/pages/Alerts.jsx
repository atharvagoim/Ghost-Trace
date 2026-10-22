import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bell, MailX, Send } from 'lucide-react'
import { api } from '../lib/api'
import { formatDate } from '../lib/format'
import { Button, EmptyState, Group, Notice, PageHeader, Row, StatusBadge } from '../components/ui'
import { useToast } from '../components/Toast'

export default function Alerts() {
  const toast = useToast()
  const [items, setItems] = useState(null)
  const [config, setConfig] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => api('/api/alerts').then(setItems).catch((e) => toast(e.message, 'error'))
  useEffect(() => {
    load()
    api('/api/alerts/config').then(setConfig).catch(() => {})
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function test() {
    setBusy(true)
    try {
      const r = await api('/api/alerts/test', { method: 'POST' })
      toast(`Test email sent to ${r.to}`)
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setBusy(false)
      load()
    }
  }

  return (
    <>
      <PageHeader title="Alerts" description="Emails GhostTrace sent when a scan or monitor found something new."
        actions={<Button variant="gray" onClick={test} loading={busy}>{!busy && <Send className="h-4 w-4" />} Send a test email</Button>} />
      {config && !config.email_configured && (
        <Notice tone="warn" icon={MailX} className="mb-6">
          Email isn’t set up on this server yet, so alerts are listed here but not sent. Add the SMTP settings to turn on delivery.
        </Notice>
      )}
      <Group footer={<>Choose which severities send an email in <Link to="/app/settings" className="text-tint-light hover:underline">Settings</Link>.</>}>
        {!items ? <div className="space-y-2 p-4"><div className="skeleton h-12" /><div className="skeleton h-12" /></div>
          : items.length === 0 ? (
            <EmptyState icon={Bell} color="#F2F2F2" title="No alerts yet">When a scan finds new high-risk credentials, the alert will appear here.</EmptyState>
          ) : items.map((a) => (
            <Row key={a.id} to={a.scan_id ? `/app/scans/${a.scan_id}` : undefined} title={a.subject}
              subtitle={`${formatDate(a.created_at)}${a.error ? ` · ${a.error}` : ''}`} trailing={<StatusBadge status={a.status} />} />
          ))}
      </Group>
    </>
  )
}
