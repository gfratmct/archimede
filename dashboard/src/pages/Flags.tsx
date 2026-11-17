import { A } from '@solidjs/router'
import { For, Show, createMemo, createSignal } from 'solid-js'
import { formatRelative, formatTs, scoreTone, type FlagRow } from '../api'
import {
  DetailGrid,
  EvidenceOverview,
  ExpandRow,
  JsonBlock,
  RiskMeter,
} from '../components/ExpandRow'
import { formatScorePct, flagInfo } from '../lib/risk'

type Props = {
  flags: () => FlagRow[] | undefined
  loading: () => boolean
  error: () => string | null
  onRefresh: () => void
}

export default function Flags(props: Props) {
  const [q, setQ] = createSignal('')
  const [kind, setKind] = createSignal<string | null>(null)

  const kinds = createMemo(() => {
    const map = new Map<string, number>()
    for (const f of props.flags() ?? []) {
      map.set(f.flag, (map.get(f.flag) ?? 0) + 1)
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1])
  })

  const filtered = createMemo(() => {
    const term = q().trim().toLowerCase()
    const k = kind()
    return (props.flags() ?? []).filter((f) => {
      if (k && f.flag !== k) return false
      if (!term) return true
      return (
        f.flag.toLowerCase().includes(term) ||
        f.message.toLowerCase().includes(term) ||
        (f.agent ?? '').toLowerCase().includes(term) ||
        (f.trace_id ?? '').toLowerCase().includes(term) ||
        f.id.toLowerCase().includes(term)
      )
    })
  })

  return (
    <div class="stack gap-md">
      <p class="lede tight">
        Security flags from policy. Expand for risk value, meaning, and linked request traces.
      </p>

      <div class="flag-kinds" role="list">
        <button
          type="button"
          class="flag-kind"
          classList={{ active: kind() === null }}
          onClick={() => setKind(null)}
        >
          <span class="flag-kind-name">ALL</span>
          <span class="flag-kind-count">{props.flags()?.length ?? 0}</span>
        </button>
        <For each={kinds()}>
          {([name, count]) => (
            <button
              type="button"
              class="flag-kind"
              classList={{ active: kind() === name }}
              onClick={() => setKind(kind() === name ? null : name)}
            >
              <span class="flag-kind-name">{name.replaceAll('_', ' ')}</span>
              <span class="flag-kind-count">{count}</span>
            </button>
          )}
        </For>
      </div>

      <div class="toolbar">
        <input
          class="input"
          placeholder="FILTER…"
          value={q()}
          onInput={(e) => setQ(e.currentTarget.value)}
        />
        <button type="button" class="btn btn-ghost" onClick={props.onRefresh}>
          REFRESH
        </button>
      </div>

      <Show when={props.error()}>{(err) => <p class="error-banner">{err()}</p>}</Show>
      <Show when={props.loading() && !props.flags()}>
        <p class="muted">LOADING FLAGS…</p>
      </Show>

      <Show when={filtered().length} fallback={<p class="muted">NO FLAGS</p>}>
        <ul class="expand-feed flag-feed">
          <For each={filtered()}>
            {(f) => {
              const info = flagInfo(f.flag)
              return (
                <ExpandRow
                  rowId={`flag:${f.id}`}
                  class="flag-item"
                  summary={
                    <div class="flag-item-top">
                      <span class={`score score-${scoreTone(f.score)}`}>
                        {formatScorePct(f.score)}
                      </span>
                      <div class="flag-summary-text">
                        <h3 class="flag-item-title">{f.flag.replaceAll('_', ' ')}</h3>
                        <p class="flag-item-msg clamp">{f.message}</p>
                        <div class="flag-item-meta">
                          <span class="mono">{f.agent ?? '—'}</span>
                          <time class="muted tiny" title={formatTs(f.ts)}>
                            {formatRelative(f.ts)}
                          </time>
                          <Show when={f.trace_id}>
                            {(id) => (
                              <A
                                class="text-link mono"
                                href={`/traces/${id()}`}
                                onClick={(e) => e.stopPropagation()}
                              >
                                TRACE {id().slice(0, 8)}
                              </A>
                            )}
                          </Show>
                        </div>
                      </div>
                    </div>
                  }
                >
                  <RiskMeter score={f.score} flag={f.flag} />
                  <EvidenceOverview evidence={f.evidence} score={f.score} />
                  <DetailGrid
                    rows={[
                      { label: 'Flag id', value: <span class="mono">{f.id}</span> },
                      { label: 'When', value: formatTs(f.ts) },
                      { label: 'Agent', value: f.agent ?? '—' },
                      { label: 'Risky value', value: formatScorePct(f.score) },
                      { label: 'Meaning', value: info.meaning },
                      {
                        label: 'PID',
                        value: f.evidence?.pid != null ? String(f.evidence.pid) : '—',
                      },
                      {
                        label: 'Process path',
                        value: f.evidence?.process_path ?? '—',
                      },
                      {
                        label: 'Trace',
                        value: f.trace_id ? (
                          <A class="text-link mono" href={`/traces/${f.trace_id}`}>
                            {f.trace_id}
                          </A>
                        ) : (
                          '—'
                        ),
                      },
                    ]}
                  />
                  <JsonBlock label="Raw flag" value={f} />
                </ExpandRow>
              )
            }}
          </For>
        </ul>
      </Show>
    </div>
  )
}
