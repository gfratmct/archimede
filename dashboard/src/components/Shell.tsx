import { A, useLocation } from '@solidjs/router'
import { For, Show, type ParentComponent } from 'solid-js'
import type { StatsSummary } from '../api'
import { formatRelative } from '../api'

const NAV = [
  { href: '/flags', label: 'FLAGS', primary: true, match: ['/', '/flags'] },
  { href: '/alerts', label: 'ALERTS', match: ['/alerts'] },
  { href: '/overview', label: 'OVERVIEW', match: ['/overview'] },
  { href: '/logs', label: 'LOGS', match: ['/logs'] },
  { href: '/traces', label: 'TRACES', match: ['/traces'] },
  { href: '/enforcement', label: 'ENFORCE', match: ['/enforcement'] },
  { href: '/config', label: 'CONFIG', match: ['/config'] },
]

type Props = {
  online: boolean
  stats?: StatsSummary
  refreshedAt: Date | null
  notifyEnabled: boolean
  onEnableNotify: () => void
  onClearAll: () => void
  clearing?: boolean
  flagCount?: number
}

function isActive(pathname: string, match: string[]): boolean {
  return match.some((m) =>
    m === '/' ? pathname === '/' : pathname === m || pathname.startsWith(`${m}/`),
  )
}

export const Shell: ParentComponent<Props> = (props) => {
  const loc = useLocation()

  const title = () =>
    NAV.find((n) => isActive(loc.pathname, n.match))?.label ?? 'MONITOR'

  return (
    <div class="shell">
      <div class="crt" aria-hidden="true" />
      <aside class="rail">
        <A href="/flags" class="brand">
          <span class="brand-mark" aria-hidden="true" />
          <span class="brand-name">ARCHIMEDE</span>
        </A>

        <nav class="nav" aria-label="Primary">
          <For each={NAV}>
            {(item) => {
              const active = () => isActive(loc.pathname, item.match)
              return (
                <A
                  href={item.href}
                  class="nav-link"
                  classList={{ active: active(), primary: !!item.primary }}
                >
                  <span>{item.label}</span>
                  <Show when={item.primary && (props.flagCount ?? 0) > 0}>
                    <span class="nav-count">{props.flagCount}</span>
                  </Show>
                </A>
              )
            }}
          </For>
        </nav>

        <div class="rail-foot">
          <div class="live-row">
            <span classList={{ pulse: true, on: props.online, off: !props.online }} />
            <span>{props.online ? 'LINK UP' : 'LINK DOWN'}</span>
          </div>
          <Show when={props.refreshedAt}>
            {(t) => <p class="muted tiny">SYNC {formatRelative(t().toISOString())}</p>}
          </Show>
          <Show when={!props.notifyEnabled}>
            <button type="button" class="ghost-btn" onClick={props.onEnableNotify}>
              ENABLE ALERTS
            </button>
          </Show>
        </div>
      </aside>

      <main class="main">
        <header class="topbar">
          <h1 class="page-title">{title()}</h1>
          <div class="topbar-actions">
            <button
              type="button"
              class="btn btn-danger"
              disabled={props.clearing}
              onClick={props.onClearAll}
              title="Delete all alerts and flags from the local store"
            >
              {props.clearing ? 'CLEARING…' : 'CLEAR ALL'}
            </button>
            <div class="top-stats">
              <div>
                <span class="tiny muted">EVT</span>
                <strong>{props.stats?.total_events ?? '—'}</strong>
              </div>
              <div>
                <span class="tiny muted">FLG</span>
                <strong>{props.flagCount ?? '—'}</strong>
              </div>
              <div>
                <span class="tiny muted">AGT</span>
                <strong>{props.stats?.agents_seen.length ?? '—'}</strong>
              </div>
            </div>
          </div>
        </header>
        <div class="content">{props.children}</div>
      </main>
    </div>
  )
}
