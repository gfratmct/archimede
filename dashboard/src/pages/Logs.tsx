import { A } from '@solidjs/router'
import { For, Show, createMemo, createSignal } from 'solid-js'
import {
  eventKindName,
  eventKindPayload,
  formatRelative,
  formatTs,
  scoreTone,
  type ArchimedeEvent,
} from '../api'
import {
  DetailGrid,
  EvidenceOverview,
  ExpandRow,
  JsonBlock,
  RiskMeter,
  evidenceFromUnknown,
} from '../components/ExpandRow'
import type { RiskEvidence } from '../api'
import { formatScorePct } from '../lib/risk'

type Props = {
  logs: () => ArchimedeEvent[] | undefined
  agents: () => string[]
  loading: () => boolean
  error: () => string | null
  onRefresh: () => void
  agentFilter: () => string
  setAgentFilter: (v: string) => void
}

function asRecord(payload: unknown): Record<string, unknown> | null {
  return payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : null
}

function summarize(ev: ArchimedeEvent): string {
  const name = eventKindName(ev.kind)
  const payload = asRecord(eventKindPayload(ev.kind))
  if (!payload) return name
  switch (name) {
    case 'classification': {
      const risk = payload.risk_score != null ? ` · risk ${formatScorePct(Number(payload.risk_score))}` : ''
      return `${payload.label} (${Math.round(Number(payload.confidence ?? 0) * 100)}% · ${payload.source}${risk})`
    }
    case 'alert':
      return `${payload.flag}: ${payload.message} · score ${formatScorePct(Number(payload.score ?? 0))}`
    case 'forecast':
      return `${payload.metric} h=${payload.horizon_steps}`
    case 'process_snapshot':
      return `${payload.comm} pid=${payload.pid} cpu=${Number(payload.cpu_pct ?? 0).toFixed(1)}%`
    case 'exec':
      return `${payload.comm} ${payload.argv_summary}`
    case 'connect':
      return `${payload.dest}:${payload.port}`
    case 'session':
      return `${payload.kind}: ${payload.summary}`
    case 'file': {
      const op = String(payload.op ?? 'edit').toLowerCase()
      const label =
        op === 'create' || op === 'created'
          ? 'created'
          : op === 'delete' || op === 'deleted' || op === 'unlink'
            ? 'deleted'
            : 'edited'
      return `${label} ${payload.path ?? ''}`.trim()
    }
    case 'span':
      return `${payload.kind}/${payload.name}`
    case 'resource_delta':
      return `pid=${payload.pid} rssΔ=${payload.rss_delta} (${payload.change_reason})`
    case 'policy_decision':
      return `${payload.flag} → ${payload.action} · score ${formatScorePct(Number(payload.score ?? 0))}`
    default:
      return JSON.stringify(payload).slice(0, 140)
  }
}

function detailRows(ev: ArchimedeEvent) {
  const name = eventKindName(ev.kind)
  const payload = asRecord(eventKindPayload(ev.kind)) ?? {}
  const base = [
    { label: 'Event id', value: <span class="mono">{ev.id}</span> },
    { label: 'When', value: formatTs(ev.ts) },
    { label: 'Source', value: ev.source },
    { label: 'Agent', value: ev.agent ?? '—' },
    { label: 'Kind', value: name },
  ]

  switch (name) {
    case 'classification': {
      const probs = asRecord(payload.probabilities) ?? {}
      const top = Object.entries(probs)
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .slice(0, 5)
        .map(([k, v]) => `${k}=${formatScorePct(Number(v))}`)
        .join(' · ')
      return [
        ...base,
        { label: 'Label', value: String(payload.label ?? '—') },
        { label: 'Confidence', value: formatScorePct(Number(payload.confidence ?? 0)) },
        {
          label: 'Risky value',
          value:
            payload.risk_score != null ? formatScorePct(Number(payload.risk_score)) : '—',
        },
        { label: 'Classifier', value: String(payload.source ?? '—') },
        { label: 'Top probs', value: top || '—' },
      ]
    }
    case 'alert':
    case 'policy_decision':
      return [
        ...base,
        { label: 'Flag', value: String(payload.flag ?? '—') },
        {
          label: 'Risky value',
          value: formatScorePct(Number(payload.score ?? 0)),
        },
        {
          label: 'Action',
          value: payload.action != null ? String(payload.action) : '—',
        },
        {
          label: 'Trace',
          value: payload.trace_id ? (
            <A class="text-link mono" href={`/traces/${payload.trace_id}`}>
              {String(payload.trace_id)}
            </A>
          ) : (
            '—'
          ),
        },
        {
          label: 'Message / reason',
          value: String(payload.message ?? payload.reason ?? '—'),
        },
      ]
    case 'span':
      return [
        ...base,
        { label: 'Span', value: String(payload.name ?? '—') },
        { label: 'Kind', value: String(payload.kind ?? '—') },
        { label: 'Model', value: String(payload.model ?? '—') },
        {
          label: 'Request',
          value: String(payload.input_summary ?? '—'),
        },
        {
          label: 'Response',
          value: String(payload.output_summary ?? '—'),
        },
        {
          label: 'Trace',
          value: payload.trace_id ? (
            <A class="text-link mono" href={`/traces/${payload.trace_id}`}>
              {String(payload.trace_id)}
            </A>
          ) : (
            '—'
          ),
        },
      ]
    case 'exec':
      return [
        ...base,
        { label: 'Comm', value: String(payload.comm ?? '—') },
        { label: 'Pid / ppid', value: `${payload.pid} / ${payload.ppid}` },
        { label: 'Argv', value: String(payload.argv_summary ?? '—') },
      ]
    case 'connect':
      return [
        ...base,
        { label: 'Dest', value: `${payload.dest}:${payload.port}` },
        { label: 'Pid', value: String(payload.pid ?? '—') },
        { label: 'SNI', value: String(payload.sni ?? '—') },
      ]
    case 'file': {
      const op = String(payload.op ?? 'edit').toLowerCase()
      const label =
        op === 'create' || op === 'created'
          ? 'created'
          : op === 'delete' || op === 'deleted' || op === 'unlink'
            ? 'deleted'
            : 'edited'
      return [
        ...base,
        { label: 'Action', value: label },
        { label: 'Path', value: String(payload.path ?? '—') },
        { label: 'Pid', value: String(payload.pid ?? '—') },
      ]
    }
    default:
      return base
  }
}

function riskScoreFor(ev: ArchimedeEvent): number | null {
  const name = eventKindName(ev.kind)
  const payload = asRecord(eventKindPayload(ev.kind))
  if (!payload) return null
  if (name === 'alert' || name === 'policy_decision') {
    return Number(payload.score ?? NaN)
  }
  if (name === 'classification' && payload.risk_score != null) {
    return Number(payload.risk_score)
  }
  return Number.isFinite(Number(payload.score)) ? Number(payload.score) : null
}

function evidenceFor(ev: ArchimedeEvent): RiskEvidence | null {
  const name = eventKindName(ev.kind)
  const payload = asRecord(eventKindPayload(ev.kind))
  if (!payload) return null
  const nested = evidenceFromUnknown(payload)
  if (nested) return nested

  if (name === 'exec') {
    return {
      pid: Number(payload.pid),
      ppid: Number(payload.ppid),
      process_name: String(payload.comm ?? ''),
      process_path: `${payload.comm ?? ''} ${payload.argv_summary ?? ''}`.trim(),
      commands: [String(payload.argv_summary ?? payload.comm ?? '')],
    }
  }
  if (name === 'process_snapshot') {
    return {
      pid: Number(payload.pid),
      ppid: Number(payload.ppid),
      process_name: String(payload.comm ?? ''),
      process_path: String(payload.cmdline ?? ''),
      cwd: payload.cwd != null ? String(payload.cwd) : null,
      commands: payload.cmdline ? [String(payload.cmdline)] : [],
    }
  }
  if (name === 'connect') {
    return {
      pid: Number(payload.pid),
      network_requests: [
        payload.sni
          ? `${payload.dest}:${payload.port} sni=${payload.sni}`
          : `${payload.dest}:${payload.port}`,
      ],
    }
  }
  if (name === 'session') {
    return {
      text_snippets: [`[${payload.kind}] ${payload.path} · ${payload.summary}`],
      process_path: payload.path != null ? String(payload.path) : null,
    }
  }
  if (name === 'file') {
    const op = String(payload.op ?? 'edit').toLowerCase()
    const label =
      op === 'create' || op === 'created'
        ? 'created'
        : op === 'delete' || op === 'deleted' || op === 'unlink'
          ? 'deleted'
          : 'edited'
    return {
      pid: payload.pid != null ? Number(payload.pid) : null,
      files: payload.path ? [`${label} ${payload.path}`] : [],
      behavior: `file:${label}`,
    }
  }
  if (name === 'span') {
    return {
      behavior: payload.kind != null ? `span:${payload.kind}` : null,
      request_summary: payload.input_summary != null ? String(payload.input_summary) : null,
      response_summary: payload.output_summary != null ? String(payload.output_summary) : null,
      text_snippets: [
        payload.input_summary ? `req: ${payload.input_summary}` : '',
        payload.output_summary ? `res: ${payload.output_summary}` : '',
      ].filter(Boolean),
      trace_id: payload.trace_id != null ? String(payload.trace_id) : null,
      span_id: payload.span_id != null ? String(payload.span_id) : null,
      commands: payload.name ? [String(payload.name)] : [],
    }
  }
  if (name === 'classification') {
    return {
      behavior: payload.label != null ? String(payload.label) : null,
      behavior_confidence:
        payload.confidence != null ? Number(payload.confidence) : null,
      risk_score: payload.risk_score != null ? Number(payload.risk_score) : null,
    }
  }
  return null
}

export default function Logs(props: Props) {
  const [q, setQ] = createSignal('')
  const filtered = createMemo(() => {
    const term = q().trim().toLowerCase()
    const list = props.logs() ?? []
    if (!term) return list
    return list.filter((ev) => {
      const blob = `${eventKindName(ev.kind)} ${ev.source} ${ev.agent ?? ''} ${summarize(ev)} ${ev.id}`.toLowerCase()
      return blob.includes(term)
    })
  })

  return (
    <div class="stack gap-md">
      <p class="lede tight">
        Live event stream. Expand any row for request/response fields, risk values, and raw JSON.
      </p>
      <div class="toolbar">
        <select
          class="input select"
          value={props.agentFilter()}
          onChange={(e) => props.setAgentFilter(e.currentTarget.value)}
        >
          <option value="">All agents</option>
          <For each={props.agents()}>{(a) => <option value={a}>{a}</option>}</For>
        </select>
        <input
          class="input"
          placeholder="Search events…"
          value={q()}
          onInput={(e) => setQ(e.currentTarget.value)}
        />
        <button type="button" class="btn btn-ghost" onClick={props.onRefresh}>
          Refresh
        </button>
      </div>
      <Show when={props.error()}>{(err) => <p class="error-banner">{err()}</p>}</Show>
      <Show when={props.loading() && !props.logs()}>
        <p class="muted">Loading logs…</p>
      </Show>
      <Show when={filtered().length} fallback={<p class="muted">No events yet.</p>}>
        <ul class="expand-feed">
          <For each={filtered()}>
            {(ev) => {
              const risk = riskScoreFor(ev)
              const name = eventKindName(ev.kind)
              return (
                <ExpandRow
                  rowId={`log:${ev.id}`}
                  summary={
                    <div class="expand-cols log-cols">
                      <time title={formatTs(ev.ts)}>{formatRelative(ev.ts)}</time>
                      <span class="kind-pill">{name}</span>
                      <span class="mono muted">{ev.agent ?? ev.source}</span>
                      <Show when={risk != null}>
                        <span class={`score score-${scoreTone(risk!)}`}>
                          {formatScorePct(risk!)}
                        </span>
                      </Show>
                      <span class="log-body clamp">{summarize(ev)}</span>
                    </div>
                  }
                >
                  <Show when={risk != null}>
                    <RiskMeter
                      score={risk!}
                      flag={
                        name === 'alert' || name === 'policy_decision'
                          ? String(asRecord(eventKindPayload(ev.kind))?.flag ?? '')
                          : name === 'classification'
                            ? 'elevated_risk_score'
                            : undefined
                      }
                    />
                  </Show>
                  <EvidenceOverview evidence={evidenceFor(ev)} score={risk ?? undefined} />
                  <DetailGrid rows={detailRows(ev)} />
                  <JsonBlock label="Raw event" value={ev} />
                </ExpandRow>
              )
            }}
          </For>
        </ul>
      </Show>
    </div>
  )
}
