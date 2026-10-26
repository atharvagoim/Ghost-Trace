import { useState } from 'react'
import { Ban, CheckCircle2, Copy, ExternalLink, GitCommit, RotateCcw, Wrench } from 'lucide-react'
import { Button, RiskMeter, SeverityBadge, Sheet, StatusBadge, riskColor } from './ui'
import { api } from '../lib/api'
import { formatDate } from '../lib/format'
import { useToast } from './Toast'
import AIPanel from './AIPanel'

const REMEDIATION = {
  aws: ['Deactivate the key in AWS IAM.', 'Create a replacement key and update your deployments.', 'Check CloudTrail for activity from the leaked key.'],
  cloud: ['Revoke the credential in your cloud console.', 'Issue a new one with the narrowest permissions.', 'Audit recent API activity.'],
  api_key: ['Regenerate the key in the provider’s dashboard.', 'Update it wherever it is used.', 'Check billing and usage logs for misuse.'],
  token: ['Revoke the token now.', 'Issue a new one with the narrowest scope possible.'],
  jwt: ['Rotate the signing secret if this token is long-lived.', 'Invalidate active sessions.'],
  private_key: ['Remove the public key from every server and account.', 'Generate a new key pair.'],
  database: ['Change the database password.', 'Restrict network access to the database.', 'Review connection logs.'],
  password: ['Change this password everywhere it is used.', 'Move it into a secrets manager or environment variable.'],
  email: ['Look the address up in Breaches.', 'Decide whether it should be public at all.'],
  webhook: ['Regenerate the webhook URL so the leaked one stops working.'],
}

const SOURCE_LABEL = { github: 'GitHub', local: 'Local repository', file: 'Uploaded file', text: 'Pasted text' }

function Stat({ label, value, color }) {
  return (
    <div className="rounded-3xl bg-white/[0.05] p-3.5">
      <div className="text-footnote text-label-2">{label}</div>
      <div className="mt-0.5 text-title2 tabular-nums" style={{ color: color || '#fff' }}>{value}</div>
    </div>
  )
}

export default function FindingDrawer({ finding, onClose, onChange }) {
  const toast = useToast()
  const [saving, setSaving] = useState(null)
  const [last, setLast] = useState(finding)
  if (finding && finding !== last) setLast(finding)
  const f = finding || last // keep content visible while the sheet slides away

  async function setStatus(status) {
    setSaving(status)
    try {
      const updated = await api(`/api/findings/${f.id}`, { method: 'PATCH', body: { status } })
      onChange?.(updated)
      toast(status === 'open' ? 'Finding reopened' : status === 'resolved' ? 'Marked as rotated' : 'Marked as not a secret')
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      setSaving(null)
    }
  }

  const location = f ? `${f.repository ? f.repository + '/' : ''}${f.file_path || ''}${f.line_number ? ':' + f.line_number : ''}` : ''
  const steps = f ? REMEDIATION[f.category] || REMEDIATION.api_key : []

  return (
    <Sheet open={Boolean(finding)} onClose={onClose} wide title={f && <span className="flex items-center gap-2"><SeverityBadge severity={f.severity} /> <StatusBadge status={f.status} /></span>}
      footer={f && (f.status === 'open' ? (
        <>
          <Button className="flex-1" onClick={() => setStatus('resolved')} loading={saving === 'resolved'}><CheckCircle2 className="h-4 w-4" /> I rotated it</Button>
          <Button className="flex-1" variant="gray" onClick={() => setStatus('false_positive')} loading={saving === 'false_positive'}><Ban className="h-4 w-4" /> Not a secret</Button>
        </>
      ) : (
        <Button className="flex-1" variant="gray" onClick={() => setStatus('open')} loading={saving === 'open'}><RotateCcw className="h-4 w-4" /> Reopen</Button>
      ))}>
      {f && (
        <div className="space-y-6">
          <div>
            <h2 className="text-title2 text-label">{f.credential_type}</h2>
            <p className="mt-1 break-all font-mono text-footnote text-label-2">{location}</p>
            {f.in_history_only && (
              <p className="mt-2 inline-flex items-center gap-1.5 rounded-full bg-ios-indigo/20 px-2.5 py-1 text-caption font-medium text-[#CFCFCF]">
                <GitCommit className="h-3.5 w-3.5" /> Deleted from the code, still in git history
              </p>
            )}
          </div>

          <div className="grid grid-cols-3 gap-2.5">
            <Stat label="Risk" value={Math.round(f.risk_score)} color={riskColor(f.risk_score)} />
            <Stat label="AI confidence" value={`${Math.round(f.confidence * 100)}%`} />
            <Stat label="Randomness" value={f.entropy.toFixed(1)} />
          </div>

          <section className="rounded-3xl bg-ios-green/10 p-4">
            <h3 className="flex items-center gap-2 text-headline text-ios-green"><Wrench className="h-4 w-4" /> What to do</h3>
            <ol className="mt-2.5 space-y-2">
              {steps.map((s, i) => (
                <li key={s} className="flex gap-3 text-subhead text-label">
                  <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-ios-green/25 text-caption font-semibold text-ios-green">{i + 1}</span>{s}
                </li>
              ))}
            </ol>
            {(f.source_type === 'github' || f.source_type === 'local') && (
              <p className="mt-3 text-footnote text-label-2">Deleting the file is not enough: the secret stays in git history until you rotate it.</p>
            )}
          </section>

          <AIPanel key={f.id} finding={f} />

          <section>
            <h3 className="field-label">Why it scored {Math.round(f.risk_score)}</h3>
            <div className="rounded-3xl bg-white/[0.05] p-4">
              <RiskMeter value={f.risk_score} wide />
              <ul className="mt-3 space-y-2">
                {(f.risk_factors || []).map((r) => (
                  <li key={r} className="flex gap-2.5 text-subhead text-label-2"><span className="mt-[9px] h-1 w-1 shrink-0 rounded-full bg-label-3" />{r}</li>
                ))}
              </ul>
            </div>
          </section>

          <section>
            <h3 className="field-label">Masked secret</h3>
            <div className="flex items-center gap-2 rounded-3xl bg-white/[0.05] px-4 py-3">
              <code className="flex-1 break-all font-mono text-subhead text-ios-teal">{f.secret_masked}</code>
              <button className="press rounded-full p-1.5 text-label-3 hover:bg-white/10 hover:text-label" aria-label="Copy fingerprint" title="Copy fingerprint"
                onClick={() => { navigator.clipboard?.writeText(f.fingerprint); toast('Fingerprint copied') }}>
                <Copy className="h-4 w-4" />
              </button>
            </div>
            <p className="mt-1.5 px-1 text-footnote text-label-3">Only this masked preview and a fingerprint are stored, never the secret itself.</p>
          </section>

          {f.snippet && (
            <section>
              <h3 className="field-label">Where it appears</h3>
              <pre className="thin-scroll overflow-x-auto rounded-3xl bg-black/50 p-4 font-mono text-footnote text-label-2">
                {f.line_number && <span className="mr-3 select-none text-label-4">{f.line_number}</span>}{f.snippet}
              </pre>
            </section>
          )}

          <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-subhead">
            <div><dt className="text-footnote text-label-3">First seen</dt><dd className="text-label">{formatDate(f.first_seen)}</dd></div>
            <div><dt className="text-footnote text-label-3">Last seen</dt><dd className="text-label">{formatDate(f.last_seen)}</dd></div>
            <div><dt className="text-footnote text-label-3">Detector</dt><dd className="font-mono text-footnote text-label">{f.rule_id}</dd></div>
            <div><dt className="text-footnote text-label-3">Source</dt><dd className="text-label">{SOURCE_LABEL[f.source_type] || f.source_type}</dd></div>
          </dl>

          {!f.url && f.commit_sha && (
            <p className="flex items-center gap-2 rounded-3xl bg-white/[0.05] px-4 py-3 font-mono text-footnote text-label-2">
              <GitCommit className="h-4 w-4 shrink-0" /> Added in commit {f.commit_sha.slice(0, 10)}
            </p>
          )}

          {f.url && (
            <Button as="a" href={f.url} target="_blank" rel="noreferrer" variant="tinted" className="w-full">
              {f.commit_sha ? <GitCommit className="h-4 w-4" /> : <ExternalLink className="h-4 w-4" />}
              {f.commit_sha ? `Open commit ${f.commit_sha.slice(0, 7)} on GitHub` : 'Open file on GitHub'}
            </Button>
          )}
        </div>
      )}
    </Sheet>
  )
}
