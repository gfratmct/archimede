import { createEffect, createSignal } from 'solid-js'
import type { AlertRow, FlagRow } from '../api'
import { useToast } from './toast'

/** Watch alert/flag streams and raise toasts + optional browser notifications. */
export function useAlertWatch(
  alerts: () => AlertRow[] | undefined,
  flags: () => FlagRow[] | undefined,
) {
  const toast = useToast()
  const [seenAlerts, setSeenAlerts] = createSignal(new Set<string>())
  const [seenFlags, setSeenFlags] = createSignal(new Set<string>())
  const [primed, setPrimed] = createSignal(false)
  const [browserOk, setBrowserOk] = createSignal(
    typeof Notification !== 'undefined' && Notification.permission === 'granted',
  )

  const requestPermission = async () => {
    if (typeof Notification === 'undefined') return
    const perm = await Notification.requestPermission()
    setBrowserOk(perm === 'granted')
  }

  createEffect(() => {
    const list = alerts()
    if (!list) return
    if (!primed()) {
      setSeenAlerts(new Set(list.map((a) => a.id)))
      return
    }
    const known = seenAlerts()
    const fresh = list.filter((a) => !known.has(a.id))
    if (fresh.length === 0) return
    for (const a of fresh.slice(0, 3)) {
      toast.push({
        tone: 'alert',
        title: a.flag.replaceAll('_', ' '),
        body: `${a.agent ?? 'unknown'} · risk ${(a.score * 100).toFixed(0)}% · ${a.message}`,
      })
      if (browserOk()) {
        try {
          new Notification(`Archimede · ${a.flag}`, {
            body: a.message,
            tag: a.id,
          })
        } catch {
          /* ignore */
        }
      }
    }
    setSeenAlerts(new Set([...known, ...fresh.map((a) => a.id)]))
  })

  createEffect(() => {
    const list = flags()
    if (!list) return
    if (!primed()) {
      setSeenFlags(new Set(list.map((f) => f.id)))
      setPrimed(true)
      return
    }
    const known = seenFlags()
    const fresh = list.filter((f) => !known.has(f.id))
    if (fresh.length === 0) return
    for (const f of fresh.slice(0, 3)) {
      toast.push({
        tone: 'alert',
        title: `Flag · ${f.flag.replaceAll('_', ' ')}`,
        body: `risk ${(f.score * 100).toFixed(0)}% · ${f.message}`,
      })
    }
    setSeenFlags(new Set([...known, ...fresh.map((f) => f.id)]))
  })

  return { browserOk, requestPermission }
}
