import { createSignal, onCleanup, onMount, type Accessor } from 'solid-js'

export type PollState<T> = {
  data: Accessor<T | undefined>
  error: Accessor<string | null>
  loading: Accessor<boolean>
  refreshedAt: Accessor<Date | null>
  refresh: () => Promise<void>
}

export type PollOptions<T> = {
  /** Merge next payload into previous (preserve object identity when possible). */
  merge?: (prev: T | undefined, next: T) => T
  /** Skip reactive update when equal — default JSON snapshot. */
  isEqual?: (a: T, b: T) => boolean
  /** Pause background ticks while document is hidden. */
  pauseWhenHidden?: boolean
}

function defaultEqual<T>(a: T, b: T): boolean {
  try {
    return JSON.stringify(a) === JSON.stringify(b)
  } catch {
    return false
  }
}

/** Merge list items by key; keep previous object refs when content is unchanged. */
export function mergeByKey<T>(
  prev: T[] | undefined,
  next: T[],
  keyOf: (item: T) => string,
): T[] {
  if (!prev?.length) return next
  const prevMap = new Map(prev.map((p) => [keyOf(p), p]))
  let changed = prev.length !== next.length
  const out = next.map((n, i) => {
    const key = keyOf(n)
    const old = prevMap.get(key)
    if (old && defaultEqual(old, n)) {
      if (prev[i] !== old) changed = true
      return old
    }
    changed = true
    return n
  })
  if (!changed) {
    let sameOrder = true
    for (let i = 0; i < prev.length; i++) {
      if (keyOf(prev[i]!) !== keyOf(next[i]!)) {
        sameOrder = false
        break
      }
    }
    if (sameOrder) return prev
  }
  return out
}

/** Merge list items by `id`; keep previous object refs when content is unchanged. */
export function mergeById<T extends { id: string }>(
  prev: T[] | undefined,
  next: T[],
): T[] {
  return mergeByKey(prev, next, (item) => item.id)
}

/** Poll an async loader on an interval; only notify Solid when data meaningfully changes. */
export function createPoll<T>(
  loader: () => Promise<T>,
  intervalMs: number = 4000,
  opts: PollOptions<T> = {},
): PollState<T> {
  const [data, setData] = createSignal<T | undefined>()
  const [error, setError] = createSignal<string | null>(null)
  const [loading, setLoading] = createSignal(true)
  const [refreshedAt, setRefreshedAt] = createSignal<Date | null>(null)

  const isEqual = opts.isEqual ?? defaultEqual
  const pauseWhenHidden = opts.pauseWhenHidden !== false

  let alive = true
  let timer: number | undefined
  let inFlight: Promise<void> | null = null

  const refresh = async () => {
    if (inFlight) return inFlight
    inFlight = (async () => {
      try {
        const raw = await loader()
        if (!alive) return
        const next = opts.merge ? opts.merge(data(), raw) : raw
        const prev = data()
        if (prev !== undefined && isEqual(prev, next)) {
          // Touch sync clock quietly without replacing list identity.
          setRefreshedAt(new Date())
          setError(null)
          return
        }
        setData(() => next)
        setError(null)
        setRefreshedAt(new Date())
      } catch (e) {
        if (!alive) return
        setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (alive) setLoading(false)
        inFlight = null
      }
    })()
    return inFlight
  }

  const schedule = () => {
    if (timer) window.clearTimeout(timer)
    timer = window.setTimeout(() => {
      void tick()
    }, intervalMs)
  }

  const tick = async () => {
    if (pauseWhenHidden && typeof document !== 'undefined' && document.hidden) {
      schedule()
      return
    }
    await refresh()
    if (alive) schedule()
  }

  const onVisibility = () => {
    if (!document.hidden && alive) void refresh()
  }

  onMount(() => {
    void tick()
    if (pauseWhenHidden) {
      document.addEventListener('visibilitychange', onVisibility)
    }
  })

  onCleanup(() => {
    alive = false
    if (timer) window.clearTimeout(timer)
    if (pauseWhenHidden) {
      document.removeEventListener('visibilitychange', onVisibility)
    }
  })

  return { data, error, loading, refreshedAt, refresh }
}
