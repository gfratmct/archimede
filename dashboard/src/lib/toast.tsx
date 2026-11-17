import {
  For,
  createContext,
  createSignal,
  onCleanup,
  useContext,
  type ParentComponent,
  type Accessor,
} from 'solid-js'

export type ToastTone = 'info' | 'alert' | 'ok'

export type ToastItem = {
  id: string
  title: string
  body?: string
  tone: ToastTone
  createdAt: number
}

type ToastApi = {
  toasts: Accessor<ToastItem[]>
  push: (toast: Omit<ToastItem, 'id' | 'createdAt'> & { id?: string }) => void
  dismiss: (id: string) => void
}

const ToastContext = createContext<ToastApi>()

export const ToastProvider: ParentComponent = (props) => {
  const [toasts, setToasts] = createSignal<ToastItem[]>([])
  const timers = new Map<string, number>()

  const dismiss = (id: string) => {
    const t = timers.get(id)
    if (t) window.clearTimeout(t)
    timers.delete(id)
    setToasts((prev) => prev.filter((x) => x.id !== id))
  }

  const push: ToastApi['push'] = (toast) => {
    const id = toast.id ?? crypto.randomUUID()
    const item: ToastItem = {
      id,
      title: toast.title,
      body: toast.body,
      tone: toast.tone,
      createdAt: Date.now(),
    }
    setToasts((prev) => [item, ...prev].slice(0, 6))
    const handle = window.setTimeout(() => dismiss(id), 7000)
    timers.set(id, handle)
  }

  onCleanup(() => {
    for (const t of timers.values()) window.clearTimeout(t)
    timers.clear()
  })

  return (
    <ToastContext.Provider value={{ toasts, push, dismiss }}>
      {props.children}
      <div class="toast-host" aria-live="polite" aria-relevant="additions">
        <For each={toasts()}>
          {(t) => (
            <button
              type="button"
              class={`toast toast-${t.tone}`}
              onClick={() => dismiss(t.id)}
            >
              <span class="toast-title">{t.title}</span>
              {t.body ? <span class="toast-body">{t.body}</span> : null}
            </button>
          )}
        </For>
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast requires ToastProvider')
  return ctx
}
