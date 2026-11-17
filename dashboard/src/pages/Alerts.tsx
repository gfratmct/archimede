import { For, Show, createMemo, createSignal } from 'solid-js'
import { formatRelative, formatTs, scoreTone, type AlertRow } from '../api'
import {
  DetailGrid,
  EvidenceOverview,
  ExpandRow,
  JsonBlock,
  RiskMeter,
} from '../components/ExpandRow'
import { formatScorePct, flagInfo } from '../lib/risk'

type Props = {
  alerts: () => AlertRow[] | undefined
  loading: () => boolean
  error: () => string | null
  onRefresh: () => void
}

export default function Alerts(props: Props) {
  const [q, setQ] = createSignal('')
  const filtered = createMemo(() => {
    const term = q().trim().toLowerCase()
    const list = props.alerts() ?? []
    if (!term) return list
    return list.filter(
      (a) =>
        a.flag.toLowerCase().includes(term) ||
        a.message.toLowerCase().includes(term) ||
        (a.agent ?? '').toLowerCase().includes(term) ||
        a.id.toLowerCase().includes(term),
    )
  })

  return (
    <div class="stack gap-md">
      <p class="lede tight">
        Expand a row for risk value, threshold comparison, and full alert payload.
      </p>
      <div class="toolbar">
        <input
          class="input"
          placeholder="Filter flag, agent, message, id…"
          value={q()}
          onInput={(e) => setQ(e.currentTarget.value)}
        />
        <button type="button" class="btn btn-ghost" onClick={props.onRefresh}>
          Refresh
        </button>
      </div>

      <Show when={props.error()}>
        {(err) => <p class="error-banner">{err()}</p>}
      </Show>
      <Show when={props.loading() && !props.alerts()}>
        <p class="muted">Loading alerts…</p>
      </Show>

      <Show when={filtered().length} fallback={<p class="muted">No alerts match.</p>}>
        <ul class="expand-feed">
          <For each={filtered()}>
            {(a) => {
              const info = flagInfo(a.flag)
              return (
                <ExpandRow
                  rowId={`alert:${a.id}`}
                  summary={
                    <div class="expand-cols alert-cols">
                      <time title={formatTs(a.ts)}>{formatRelative(a.ts)}</time>
                      <span class="mono flag">{a.flag}</span>
                      <span>{a.agent ?? '—'}</span>
                      <span class={`score score-${scoreTone(a.score)}`}>
                        {formatScorePct(a.score)}
                      </span>
                      <span class="clamp">{a.message}</span>
                    </div>
                  }
                >
                  <RiskMeter score={a.score} flag={a.flag} />
                  <EvidenceOverview evidence={a.evidence} score={a.score} />
                  <DetailGrid
                    rows={[
                      { label: 'Alert id', value: <span class="mono">{a.id}</span> },
                      { label: 'When', value: formatTs(a.ts) },
                      { label: 'Agent', value: a.agent ?? '—' },
                      { label: 'Flag', value: info.title },
                      { label: 'Risky value', value: formatScorePct(a.score) },
                      {
                        label: 'PID',
                        value: a.evidence?.pid != null ? String(a.evidence.pid) : '—',
                      },
                      {
                        label: 'Process path',
                        value: a.evidence?.process_path ?? '—',
                      },
                      { label: 'Message', value: a.message },
                    ]}
                  />
                  <JsonBlock label="Raw alert" value={a} />
                </ExpandRow>
              )
            }}
          </For>
        </ul>
      </Show>
    </div>
  )
}
