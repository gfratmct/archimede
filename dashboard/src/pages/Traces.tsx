import { A, useParams } from '@solidjs/router'
import { For, Show, createMemo, createResource, createSignal } from 'solid-js'
import {
  api,
  formatRelative,
  formatTs,
  type SpanRecord,
  type TraceRecord,
} from '../api'
import {
  DetailGrid,
  EvidenceOverview,
  ExpandRow,
  JsonBlock,
  RiskMeter,
} from '../components/ExpandRow'
import { createPoll, mergeByKey } from '../lib/poll'
import { spanDurationMs } from '../lib/risk'

export function TracesList() {
  const [agent, setAgent] = createSignal('')
  const poll = createPoll(() => api.traces(80, agent() || undefined), 8000, {
    merge: (prev, next) => mergeByKey(prev, next, (t) => t.trace_id),
  })
  const [q, setQ] = createSignal('')
  const filtered = createMemo(() => {
    const term = q().trim().toLowerCase()
    const list = poll.data() ?? []
    if (!term) return list
    return list.filter((t) =>
      `${t.trace_id} ${t.name ?? ''} ${t.agent ?? ''} ${t.harness ?? ''} ${t.session_id ?? ''}`
        .toLowerCase()
        .includes(term),
    )
  })

  return (
    <div class="stack gap-md">
      <p class="lede tight">
        Harness / LLM traces. Open a trace for per-span request and response detail.
      </p>
      <div class="toolbar">
        <input
          class="input"
          placeholder="Filter agent / harness / id…"
          value={q()}
          onInput={(e) => setQ(e.currentTarget.value)}
        />
        <input
          class="input"
          placeholder="Agent filter (API)"
          value={agent()}
          onInput={(e) => setAgent(e.currentTarget.value)}
        />
        <button type="button" class="btn btn-ghost" onClick={() => void poll.refresh()}>
          Refresh
        </button>
      </div>
      <Show when={poll.error()}>{(err) => <p class="error-banner">{err()}</p>}</Show>
      <Show when={filtered().length} fallback={<p class="muted">No traces ingested yet.</p>}>
        <ul class="expand-feed">
          <For each={filtered()}>
            {(t: TraceRecord) => (
              <ExpandRow
                rowId={`trace:${t.trace_id}`}
                summary={
                  <div class="expand-cols trace-cols">
                    <time title={formatTs(t.start_ts)}>{formatRelative(t.start_ts)}</time>
                    <span>{t.name ?? '—'}</span>
                    <span>{t.agent ?? '—'}</span>
                    <span>{t.harness ?? '—'}</span>
                    <A
                      class="text-link mono"
                      href={`/traces/${t.trace_id}`}
                      onClick={(e) => e.stopPropagation()}
                    >
                      {t.trace_id.slice(0, 12)}…
                    </A>
                  </div>
                }
              >
                <DetailGrid
                  rows={[
                    { label: 'Trace id', value: <span class="mono">{t.trace_id}</span> },
                    { label: 'Name', value: t.name ?? '—' },
                    { label: 'Agent', value: t.agent ?? '—' },
                    { label: 'Harness', value: t.harness ?? '—' },
                    { label: 'User', value: t.user_id ?? '—' },
                    { label: 'Session', value: t.session_id ?? '—' },
                    {
                      label: 'Window',
                      value: `${formatTs(t.start_ts)}${t.end_ts ? ` → ${formatTs(t.end_ts)}` : ' · open'}`,
                    },
                    {
                      label: 'Open detail',
                      value: (
                        <A class="text-link" href={`/traces/${t.trace_id}`}>
                          Full span tree →
                        </A>
                      ),
                    },
                  ]}
                />
                <JsonBlock label="Trace metadata" value={t.metadata} />
              </ExpandRow>
            )}
          </For>
        </ul>
      </Show>
    </div>
  )
}

function SpanCard(props: { span: SpanRecord }) {
  const s = () => props.span
  const dur = () => spanDurationMs(s().start_ts, s().end_ts)
  const tokens = () => s().token_usage

  return (
    <ExpandRow
      rowId={`span:${s().trace_id}:${s().span_id}`}
      summary={
        <div class="expand-cols span-cols">
          <time title={formatTs(s().start_ts)}>{formatRelative(s().start_ts)}</time>
          <span class="kind-pill">{s().kind}</span>
          <span class="mono">{s().name}</span>
          <span class="log-body clamp">
            {s().model ? `${s().model} · ` : ''}
            {s().status ?? '—'}
            {s().input_summary ? ` · req: ${s().input_summary}` : ''}
          </span>
        </div>
      }
    >
      <DetailGrid
        rows={[
          { label: 'Span id', value: <span class="mono">{s().span_id}</span> },
          {
            label: 'Parent',
            value: s().parent_span_id ? (
              <span class="mono">{s().parent_span_id}</span>
            ) : (
              'root'
            ),
          },
          { label: 'Kind', value: s().kind },
          { label: 'Status', value: s().status ?? '—' },
          { label: 'Model', value: s().model ?? '—' },
          {
            label: 'Duration',
            value: dur() != null ? `${dur()} ms` : 'open / unknown',
          },
          {
            label: 'Tokens',
            value: tokens()
              ? `in=${tokens()!.input ?? '—'} out=${tokens()!.output ?? '—'} total=${tokens()!.total ?? '—'}`
              : '—',
          },
          { label: 'Agent', value: s().agent ?? '—' },
          { label: 'Harness', value: s().harness ?? '—' },
        ]}
      />
      <div class="request-pair">
        <div>
          <p class="tiny muted">Request / input</p>
          <pre class="code-block tight">{s().input_summary ?? '—'}</pre>
        </div>
        <div>
          <p class="tiny muted">Response / output</p>
          <pre class="code-block tight">{s().output_summary ?? '—'}</pre>
        </div>
      </div>
      <JsonBlock label="Span attrs" value={s().attrs} />
      <JsonBlock label="Raw span" value={s()} />
    </ExpandRow>
  )
}

export function TraceDetail() {
  const params = useParams()
  const [tree] = createResource(
    () => params.id,
    (id) => api.trace(id),
  )
  const [flags] = createResource(
    () => params.id,
    (id) => api.flags(40, undefined, id),
  )

  return (
    <div class="stack gap-md">
      <A class="text-link" href="/traces">
        ← All traces
      </A>
      <Show when={tree.error}>
        <p class="error-banner">{String(tree.error)}</p>
      </Show>
      <Show when={tree.loading}>
        <p class="muted">Loading trace…</p>
      </Show>
      <Show when={tree()}>
        {(t) => (
          <>
            <section class="detail-panel">
              <h3 class="mono">{t().trace.trace_id}</h3>
              <p>
                {t().trace.name ?? 'unnamed'} · {t().trace.agent ?? '—'} ·{' '}
                {t().trace.harness ?? '—'}
              </p>
              <p class="tiny muted">
                {formatTs(t().trace.start_ts)}
                {t().trace.end_ts ? ` → ${formatTs(t().trace.end_ts!)}` : ' · open'}
                {t().trace.session_id ? ` · session ${t().trace.session_id}` : ''}
                {t().trace.user_id ? ` · user ${t().trace.user_id}` : ''}
              </p>
              <JsonBlock label="Trace metadata" value={t().trace.metadata} />
            </section>

            <Show when={(flags() ?? []).length}>
              <section>
                <div class="section-head">
                  <h3>Linked flags ({flags()?.length ?? 0})</h3>
                </div>
                <ul class="expand-feed">
                  <For each={flags() ?? []}>
                    {(f) => (
                      <ExpandRow
                        rowId={`trace-flag:${f.id}`}
                        summary={
                          <div class="expand-cols alert-cols">
                            <time>{formatRelative(f.ts)}</time>
                            <span class="mono flag">{f.flag}</span>
                            <span>{f.agent ?? '—'}</span>
                            <span class="score">{formatScorePctSafe(f.score)}</span>
                            <span class="clamp">{f.message}</span>
                          </div>
                        }
                      >
                        <RiskMeter score={f.score} flag={f.flag} />
                        <EvidenceOverview evidence={f.evidence} score={f.score} />
                        <JsonBlock label="Raw flag" value={f} />
                      </ExpandRow>
                    )}
                  </For>
                </ul>
              </section>
            </Show>

            <section>
              <div class="section-head">
                <h3>Spans ({t().spans.length})</h3>
              </div>
              <Show
                when={t().spans.length}
                fallback={<p class="muted">No spans on this trace.</p>}
              >
                <ul class="expand-feed">
                  <For each={t().spans}>{(s) => <SpanCard span={s} />}</For>
                </ul>
              </Show>
            </section>
          </>
        )}
      </Show>
    </div>
  )
}

function formatScorePctSafe(score: number): string {
  return `${(score * 100).toFixed(0)}%`
}
