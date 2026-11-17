import { A } from '@solidjs/router'
import { For, Show, createSignal, type JSX, type ParentProps } from 'solid-js'
import {
  formatScorePct,
  flagInfo,
  prettyJson,
  riskLevel,
  riskLevelLabel,
  scoreVsThreshold,
  DEFAULT_RISK_THRESHOLD,
} from '../lib/risk'
import { scoreTone, type RiskEvidence } from '../api'
import { isRowExpanded, toggleRowExpanded } from '../lib/expandState'

type ExpandRowProps = ParentProps<{
  /** Stable id — expanded state survives poll refreshes / remounts. */
  rowId?: string
  summary: JSX.Element
  open?: boolean
  class?: string
  classList?: Record<string, boolean | undefined>
}>

/** Click-to-expand list row used by alerts, flags, logs, and spans. */
export function ExpandRow(props: ExpandRowProps) {
  const [localOpen, setLocalOpen] = createSignal(props.open ?? false)

  const open = () => (props.rowId ? isRowExpanded(props.rowId) : localOpen())

  const toggle = () => {
    if (props.rowId) toggleRowExpanded(props.rowId)
    else setLocalOpen(!localOpen())
  }

  return (
    <li class={props.class} classList={{ 'expand-row': true, open: open(), ...props.classList }}>
      <div
        class="expand-summary"
        role="button"
        tabindex={0}
        aria-expanded={open()}
        onClick={toggle}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            toggle()
          }
        }}
      >
        <span class="expand-caret" aria-hidden="true">
          {open() ? '▾' : '▸'}
        </span>
        <div class="expand-summary-body">{props.summary}</div>
      </div>
      <Show when={open()}>
        <div class="expand-panel">{props.children}</div>
      </Show>
    </li>
  )
}

type KV = { label: string; value: JSX.Element | string | number | null | undefined }

export function DetailGrid(props: { rows: KV[] }) {
  return (
    <dl class="detail-grid">
      <For each={props.rows}>
        {(row) => (
          <div class="detail-cell">
            <dt>{row.label}</dt>
            <dd>{row.value ?? '—'}</dd>
          </div>
        )}
      </For>
    </dl>
  )
}

export function JsonBlock(props: { value: unknown; label?: string }) {
  return (
    <div class="json-block">
      <Show when={props.label}>
        <p class="tiny muted">{props.label}</p>
      </Show>
      <pre class="code-block tight">{prettyJson(props.value)}</pre>
    </div>
  )
}

export function RiskMeter(props: {
  score: number
  threshold?: number
  flag?: string
}) {
  const threshold = () => props.threshold ?? DEFAULT_RISK_THRESHOLD
  const vs = () => scoreVsThreshold(props.score, threshold())
  const level = () => riskLevel(props.score)
  const info = () => (props.flag ? flagInfo(props.flag) : null)
  const pct = () => Math.round(Math.min(1, Math.max(0, props.score)) * 100)

  return (
    <div class="risk-meter">
      <div class="risk-meter-top">
        <span class={`score score-${scoreTone(props.score)}`}>{formatScorePct(props.score)}</span>
        <span class={`risk-level risk-${level()}`}>{riskLevelLabel(props.score)}</span>
        <span class="muted tiny">
          threshold {vs().thresholdPct}% ·{' '}
          {vs().over ? `+${vs().deltaPct} pts over` : `${Math.abs(vs().deltaPct)} pts under`}
        </span>
      </div>
      <div class="risk-bar" role="meter" aria-valuenow={pct()} aria-valuemin={0} aria-valuemax={100}>
        <div class={`risk-bar-fill risk-${level()}`} style={{ width: `${pct()}%` }} />
        <div class="risk-bar-mark" style={{ left: `${threshold() * 100}%` }} title="threshold" />
      </div>
      <Show when={info()}>
        {(i) => (
          <div class="risk-copy">
            <p>
              <strong>{i().title}</strong> — {i().meaning}
            </p>
            <p class="muted tiny">Watch: {i().watch}</p>
          </div>
        )}
      </Show>
    </div>
  )
}

function hasEvidence(e?: RiskEvidence | null): boolean {
  if (!e) return false
  return Boolean(
    e.pid != null ||
      e.process_path ||
      e.process_name ||
      e.cwd ||
      (e.commands && e.commands.length) ||
      e.behavior ||
      (e.text_snippets && e.text_snippets.length) ||
      (e.network_requests && e.network_requests.length) ||
      (e.remotes && e.remotes.length) ||
      e.request_summary ||
      e.response_summary ||
      e.trace_id,
  )
}

function ListBlock(props: { title: string; items?: string[] | null }) {
  return (
    <Show when={(props.items ?? []).length}>
      <div class="evidence-block">
        <p class="tiny muted">{props.title}</p>
        <ul class="evidence-list">
          <For each={props.items ?? []}>{(item) => <li class="mono">{item}</li>}</For>
        </ul>
      </div>
    </Show>
  )
}

/** Full process / command / behavior / network overview for an alert or flag. */
export function EvidenceOverview(props: { evidence?: RiskEvidence | null; score?: number }) {
  const e = () => props.evidence
  return (
    <Show when={hasEvidence(e())}>
      <section class="evidence-overview">
        <div class="section-head tight">
          <h4>CONTEXT OVERVIEW</h4>
        </div>
        <DetailGrid
          rows={[
            {
              label: 'PID',
              value:
                e()?.pid != null
                  ? `${e()!.pid}${e()?.ppid != null ? ` (ppid ${e()!.ppid})` : ''}`
                  : '—',
            },
            { label: 'Process', value: e()?.process_name ?? '—' },
            {
              label: 'Process path / cmdline',
              value: e()?.process_path ? (
                <span class="mono wrap">{e()!.process_path}</span>
              ) : (
                '—'
              ),
            },
            { label: 'CWD', value: e()?.cwd ? <span class="mono wrap">{e()!.cwd}</span> : '—' },
            {
              label: 'Behavior',
              value: e()?.behavior
                ? `${e()!.behavior}${
                    e()?.behavior_confidence != null
                      ? ` · ${formatScorePct(e()!.behavior_confidence!)}`
                      : ''
                  }`
                : '—',
            },
            {
              label: 'Risky value',
              value:
                e()?.risk_score != null
                  ? formatScorePct(e()!.risk_score!)
                  : props.score != null
                    ? formatScorePct(props.score)
                    : '—',
            },
            {
              label: 'Trace',
              value: e()?.trace_id ? (
                <A class="text-link mono" href={`/traces/${e()!.trace_id}`}>
                  {e()!.trace_id}
                </A>
              ) : (
                '—'
              ),
            },
            { label: 'Span', value: e()?.span_id ? <span class="mono">{e()!.span_id}</span> : '—' },
          ]}
        />

        <ListBlock title="Risky pieces (validate)" items={e()?.text_snippets} />
        <ListBlock title="Commands / argv" items={e()?.commands} />
        <ListBlock title="Network requests" items={e()?.network_requests} />
        <ListBlock title="Remotes" items={e()?.remotes} />
        <ListBlock title="Binaries" items={e()?.binaries} />
        <ListBlock title="Files" items={e()?.files} />

        <Show when={e()?.request_summary || e()?.response_summary}>
          <div class="request-pair">
            <div>
              <p class="tiny muted">Request / input</p>
              <pre class="code-block tight">{e()?.request_summary ?? '—'}</pre>
            </div>
            <div>
              <p class="tiny muted">Response / output</p>
              <pre class="code-block tight">{e()?.response_summary ?? '—'}</pre>
            </div>
          </div>
        </Show>
      </section>
    </Show>
  )
}

/** Pull evidence from an alert/flag row or nested event payload. */
export function evidenceFromUnknown(value: unknown): RiskEvidence | null {
  if (!value || typeof value !== 'object') return null
  const obj = value as Record<string, unknown>
  if (obj.evidence && typeof obj.evidence === 'object') {
    return obj.evidence as RiskEvidence
  }
  // PolicyDecision embeds evidence at top level alongside pid.
  if (
    obj.pid != null ||
    obj.process_path ||
    obj.commands ||
    obj.network_requests ||
    obj.text_snippets
  ) {
    return obj as RiskEvidence
  }
  return null
}
