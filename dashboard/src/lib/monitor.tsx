import {
  createContext,
  createEffect,
  createMemo,
  createSignal,
  useContext,
  type ParentComponent,
  type Accessor,
} from 'solid-js'
import { api, type AlertRow, type ArchimedeEvent, type FlagRow, type StatsSummary } from '../api'
import { clearExpanded } from './expandState'
import { useAlertWatch } from './notify'
import { createPoll, mergeById, type PollState } from './poll'
import { useToast } from './toast'

type MonitorApi = {
  stats: PollState<StatsSummary>
  alerts: PollState<AlertRow[]>
  flags: PollState<FlagRow[]>
  logs: PollState<ArchimedeEvent[]>
  health: PollState<{ ok: boolean; service: string }>
  agents: Accessor<string[]>
  online: Accessor<boolean>
  agentFilter: Accessor<string>
  setAgentFilter: (v: string) => void
  browserOk: Accessor<boolean>
  requestPermission: () => Promise<void>
  clearAll: () => Promise<void>
  clearing: Accessor<boolean>
}

const MonitorContext = createContext<MonitorApi>()

export const MonitorProvider: ParentComponent = (props) => {
  const toast = useToast()
  const [agentFilter, setAgentFilter] = createSignal('')
  const [clearing, setClearing] = createSignal(false)
  const stats = createPoll(() => api.stats(), 8000)
  const alerts = createPoll(() => api.alerts(80), 8000, { merge: mergeById })
  const flags = createPoll(() => api.flags(80), 8000, { merge: mergeById })
  const logs = createPoll(() => api.logs(100, agentFilter() || undefined), 8000, {
    merge: mergeById,
  })
  const health = createPoll(() => api.health(), 12000)

  let agentFilterPrimed = false
  createEffect(() => {
    const filter = agentFilter()
    if (!agentFilterPrimed) {
      agentFilterPrimed = true
      return
    }
    void filter
    void logs.refresh()
  })

  const { browserOk, requestPermission } = useAlertWatch(alerts.data, flags.data)
  const online = createMemo(() => !!health.data()?.ok && !health.error())
  const agents = createMemo(() => stats.data()?.agents_seen ?? [])

  const clearAll = async () => {
    if (clearing()) return
    const ok = window.confirm('Clear all alerts and flags from the local store?')
    if (!ok) return
    setClearing(true)
    try {
      const result = await api.clear()
      clearExpanded()
      await Promise.all([alerts.refresh(), flags.refresh(), stats.refresh()])
      toast.push({
        tone: 'ok',
        title: 'Cleared',
        body: `${result.cleared_flags} flags · ${result.cleared_alerts} alerts`,
      })
    } catch (e) {
      toast.push({
        tone: 'alert',
        title: 'Clear failed',
        body: e instanceof Error ? e.message : String(e),
      })
    } finally {
      setClearing(false)
    }
  }

  const value: MonitorApi = {
    stats,
    alerts,
    flags,
    logs,
    health,
    agents,
    online,
    agentFilter,
    setAgentFilter,
    browserOk,
    requestPermission,
    clearAll,
    clearing,
  }

  return <MonitorContext.Provider value={value}>{props.children}</MonitorContext.Provider>
}

export function useMonitor(): MonitorApi {
  const ctx = useContext(MonitorContext)
  if (!ctx) throw new Error('useMonitor requires MonitorProvider')
  return ctx
}
