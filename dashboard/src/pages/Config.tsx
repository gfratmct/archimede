import { Show } from 'solid-js'
import { createPoll } from '../lib/poll'
import { api } from '../api'

export default function Config() {
  const poll = createPoll(() => api.config(), 15000)

  return (
    <div class="stack gap-md">
      <div class="toolbar">
        <p class="muted">Resolved daemon config (read-only).</p>
        <button type="button" class="btn btn-ghost" onClick={() => void poll.refresh()}>
          Refresh
        </button>
      </div>
      <Show when={poll.error()}>{(err) => <p class="error-banner">{err()}</p>}</Show>
      <Show when={poll.data()} fallback={<p class="muted">Loading config…</p>}>
        {(cfg) => <pre class="code-block">{JSON.stringify(cfg(), null, 2)}</pre>}
      </Show>
    </div>
  )
}
