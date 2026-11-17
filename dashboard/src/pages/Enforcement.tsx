import { For, Show } from 'solid-js'
import { formatRelative, formatTs } from '../api'
import { createPoll } from '../lib/poll'
import { api } from '../api'

export default function Enforcement() {
  const poll = createPoll(() => api.enforcement(80), 10000)
  const data = () => poll.data()

  return (
    <div class="stack gap-md">
      <section class="split">
        <div class="stat wide">
          <span class="tiny muted">Enforcement</span>
          <strong classList={{ 'warn-text': !!data()?.enforcement_enabled }}>
            {data()
              ? data()!.enforcement_enabled
                ? 'ENABLED'
                : 'observe-only'
              : '—'}
          </strong>
          <p class="muted tiny">
            Default is observe + alert. Actions run only when enabled in config.
          </p>
        </div>
        <div>
          <div class="section-head">
            <h3>Allowlist</h3>
          </div>
          <Show
            when={(data()?.actions_allowlist ?? []).length}
            fallback={<p class="muted">No actions allowlisted.</p>}
          >
            <ul class="chip-list">
              <For each={data()?.actions_allowlist ?? []}>
                {(a) => <li class="chip">{a}</li>}
              </For>
            </ul>
          </Show>
        </div>
      </section>

      <div class="toolbar">
        <button type="button" class="btn btn-ghost" onClick={() => void poll.refresh()}>
          Refresh
        </button>
      </div>
      <Show when={poll.error()}>{(err) => <p class="error-banner">{err()}</p>}</Show>
      <Show
        when={(data()?.recent ?? []).length}
        fallback={<p class="muted">No enforcement actions recorded.</p>}
      >
        <ul class="table-list">
          <li class="table-head cols-6">
            <span>When</span>
            <span>Flag</span>
            <span>Action</span>
            <span>Agent</span>
            <span>Enforced</span>
            <span>Reason</span>
          </li>
          <For each={data()?.recent ?? []}>
            {(r) => (
              <li class="table-row cols-6">
                <span title={formatTs(r.ts)}>{formatRelative(r.ts)}</span>
                <span class="mono flag">{r.flag}</span>
                <span class="mono">{r.action}</span>
                <span>{r.agent ?? '—'}</span>
                <span classList={{ 'warn-text': r.enforced }}>{r.enforced ? 'yes' : 'no'}</span>
                <span>{r.reason}</span>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </div>
  )
}
