import { For, Show, createMemo, createResource } from 'solid-js'
import { A } from '@solidjs/router'
import {
  api,
  formatRelative,
  scoreTone,
  type AlertRow,
  type StatsSummary,
} from '../api'
import { Sparkline } from '../components/Sparkline'

type Props = {
  stats: () => StatsSummary | undefined
  alerts: () => AlertRow[] | undefined
  flagCount?: () => number
}

export default function Overview(props: Props) {
  const agents = createMemo(() => props.stats()?.agents_seen ?? [])
  const primaryAgent = createMemo(() => agents()[0])
  const cls = createMemo(() => props.stats()?.last_classification)

  const [series] = createResource(
    () => primaryAgent(),
    async (agent) => {
      if (!agent) return [] as number[]
      try {
        const points = await api.metrics(agent, 'exec_count', 48)
        return points.map((p) => p.value)
      } catch {
        return [] as number[]
      }
    },
  )

  return (
    <div class="stack gap-lg">
      <section class="hero-panel">
        <div class="hero-copy">
          <p class="eyebrow">STATION ONLINE</p>
          <h2>WATCH THE AGENTS</h2>
          <p class="lede">Classify. Forecast. Flag risk. Minimal noise.</p>
          <div class="hero-actions">
            <A class="btn" href="/flags">
              OPEN FLAGS
            </A>
            <A class="btn btn-ghost" href="/alerts">
              ALERTS
            </A>
          </div>
        </div>
        <div class="hero-meter">
          <div class="meter-head">
            <span>EXEC</span>
            <Show when={primaryAgent()} fallback={<span class="muted">—</span>}>
              {(a) => <span class="mono">{a()}</span>}
            </Show>
          </div>
          <Show
            when={(series() ?? []).length > 1}
            fallback={<p class="muted">AWAITING SERIES</p>}
          >
            <Sparkline values={series() ?? []} width={280} height={64} class="sparkline xl" />
          </Show>
        </div>
      </section>

      <section class="grid-4">
        <div class="stat">
          <span class="tiny muted">BUCKETS</span>
          <strong>{props.stats()?.buckets ?? '—'}</strong>
        </div>
        <div class="stat">
          <span class="tiny muted">TRACES</span>
          <strong>{props.stats()?.traces ?? '—'}</strong>
        </div>
        <div class="stat">
          <span class="tiny muted">SPANS</span>
          <strong>{props.stats()?.spans ?? '—'}</strong>
        </div>
        <A class="stat link-stat" href="/flags">
          <span class="tiny muted">FLAGS</span>
          <strong>{props.flagCount?.() ?? props.stats()?.alerts ?? '—'}</strong>
        </A>
      </section>

      <section class="split">
        <div>
          <div class="section-head">
            <h3>AGENTS</h3>
          </div>
          <Show when={agents().length} fallback={<p class="muted">NONE YET</p>}>
            <ul class="chip-list">
              <For each={agents()}>{(a) => <li class="chip">{a}</li>}</For>
            </ul>
          </Show>
        </div>
        <div>
          <div class="section-head">
            <h3>CLASSIFY</h3>
          </div>
          <Show when={cls()} fallback={<p class="muted">WAITING</p>}>
            {(c) => (
              <div class="classify-block">
                <p class="label-pill">{c().label}</p>
                <p>
                  <span class="mono">{c().agent}</span>
                  <span class="muted">
                    {' '}
                    · conf {(c().confidence * 100).toFixed(0)}% · {c().source}
                  </span>
                </p>
                <Show when={c().risk_score != null}>
                  <p class={`tiny score-${scoreTone(c().risk_score!)}`}>
                    risk {(c().risk_score! * 100).toFixed(0)}%
                  </p>
                </Show>
              </div>
            )}
          </Show>
        </div>
      </section>

      <section>
        <div class="section-head">
          <h3>RECENT ALERTS</h3>
          <A href="/alerts" class="text-link">
            ALL
          </A>
        </div>
        <Show
          when={(props.alerts() ?? []).length}
          fallback={<p class="muted">QUIET</p>}
        >
          <ul class="feed">
            <For each={(props.alerts() ?? []).slice(0, 5)}>
              {(a) => (
                <li class="feed-row">
                  <span class={`score score-${scoreTone(a.score)}`}>
                    {(a.score * 100).toFixed(0)}%
                  </span>
                  <div>
                    <p class="feed-title">{a.flag.replaceAll('_', ' ')}</p>
                    <p class="muted tiny">
                      {a.agent ?? '—'} · {formatRelative(a.ts)} · risk{' '}
                      {(a.score * 100).toFixed(0)}%
                    </p>
                  </div>
                  <p class="feed-msg">{a.message}</p>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </section>
    </div>
  )
}
