import { useEffect, useState } from 'react'
import { api } from './api'

// Server limits (upload size, monitoring cadence, serverless mode). Fetched once and shared.
let cached = null
let pending = null
const FALLBACK = { serverless: false, max_upload_mb: 20, monitor_cadence: 'every hour', scan_time_limit_seconds: null, persistent_storage: true }

export function useMeta() {
  const [meta, setMeta] = useState(cached || FALLBACK)
  useEffect(() => {
    if (cached) return
    pending ||= api('/api/meta').then((m) => (cached = m)).catch(() => FALLBACK)
    pending.then(setMeta)
  }, [])
  return meta
}
