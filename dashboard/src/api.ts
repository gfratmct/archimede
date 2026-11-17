export type ClassificationRow = {
  ts: string
  agent: string
  label: string
  confidence: number
  source: string
  risk_score?: number | null
  probabilities?: Record<string, number>
}

export type StatsSummary = {
  total_events: number
  agents_seen: string[]
  alerts: number
  traces: number
  spans: number
  last_classification: ClassificationRow | null
  buckets: number
}

export type RiskEvidence = {
  pid?: number | null
  ppid?: number | null
  process_name?: string | null
  process_path?: string | null
  cwd?: string | null
  commands?: string[]
  behavior?: string | null
  behavior_confidence?: number | null
  risk_score?: number | null
  text_snippets?: string[]
  network_requests?: string[]
  remotes?: string[]
  binaries?: string[]
  files?: string[]
  trace_id?: string | null
  span_id?: string | null
  request_summary?: string | null
  response_summary?: string | null
}

export type AlertRow = {
  id: string
  ts: string
  agent: string | null
  flag: string
  message: string
  score: number
  evidence?: RiskEvidence
}

export type FlagRow = AlertRow & {
  trace_id: string | null
}

export type EnforcementRow = {
  id: string
  ts: string
  agent: string | null
  flag: string
  action: string
  reason: string
  pid: number | null
  trace_id: string | null
  enforced: boolean
}

export type EnforcementResponse = {
  enforcement_enabled: boolean
  actions_allowlist: string[]
  recent: EnforcementRow[]
}

export type MetricPoint = {
  ts: string
  agent: string
  metric: string
  value: number
}

export type TraceRecord = {
  trace_id: string
  name: string | null
  agent: string | null
  harness: string | null
  user_id: string | null
  session_id: string | null
  metadata: unknown
  start_ts: string
  end_ts: string | null
}

export type SpanRecord = {
  trace_id: string
  span_id: string
  parent_span_id: string | null
  name: string
  kind: string
  agent: string | null
  harness: string | null
  model: string | null
  input_summary: string | null
  output_summary: string | null
  attrs: unknown
  start_ts: string
  end_ts: string | null
  status: string | null
  token_usage: { input?: number; output?: number; total?: number } | null
}

export type TraceTree = {
  trace: TraceRecord
  spans: SpanRecord[]
}

export type ArchimedeEvent = {
  id: string
  ts: string
  source: string
  agent: string | null
  kind: Record<string, unknown>
}

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(path, window.location.origin)
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== '') url.searchParams.set(k, String(v))
    }
  }
  const res = await fetch(url)
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`${res.status} ${path}: ${body || res.statusText}`)
  }
  return res.json() as Promise<T>
}

function apiToken(): string | null {
  try {
    return localStorage.getItem('archimede_api_token')
  } catch {
    return null
  }
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const token = apiToken()
  if (token) headers['X-Archimede-Token'] = token
  const res = await fetch(path, {
    method: 'POST',
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${path}: ${text || res.statusText}`)
  }
  return res.json() as Promise<T>
}

export type ClearResult = {
  ok: boolean
  cleared_alerts: number
  cleared_flags: number
}

export const api = {
  health: () => get<{ ok: boolean; service: string }>('/health'),
  stats: () => get<StatsSummary>('/v1/stats'),
  alerts: (limit = 50) => get<AlertRow[]>('/v1/alerts', { limit }),
  flags: (limit = 50, agent?: string, traceId?: string) =>
    get<FlagRow[]>('/v1/flags', { limit, agent, trace_id: traceId }),
  logs: (limit = 80, agent?: string) => get<ArchimedeEvent[]>('/v1/logs', { limit, agent }),
  traces: (limit = 50, agent?: string) => get<TraceRecord[]>('/v1/traces', { limit, agent }),
  trace: (id: string) => get<TraceTree>(`/v1/traces/${id}`),
  enforcement: (limit = 50) => get<EnforcementResponse>('/v1/enforcement', { limit }),
  metrics: (agent: string, metric: string, limit = 64) =>
    get<MetricPoint[]>('/v1/metrics', { agent, metric, limit }),
  config: () => get<Record<string, unknown>>('/v1/config'),
  clear: () => post<ClearResult>('/v1/clear'),
}

export function eventKindName(kind: Record<string, unknown>): string {
  const keys = Object.keys(kind)
  return keys[0] ?? 'unknown'
}

export function eventKindPayload(kind: Record<string, unknown>): unknown {
  const key = eventKindName(kind)
  return key === 'unknown' ? null : kind[key]
}

export function formatTs(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatRelative(ts: string): string {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (Number.isNaN(diff)) return '—'
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 48) return `${hr}h ago`
  return formatTs(ts)
}

export function scoreTone(score: number): 'low' | 'mid' | 'high' {
  if (score >= 0.7) return 'high'
  if (score >= 0.4) return 'mid'
  return 'low'
}
