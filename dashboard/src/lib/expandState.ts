import { createSignal } from 'solid-js'

/** Survives list remounts / silent poll updates so expanded rows stay open. */
const [expanded, setExpanded] = createSignal<Record<string, true>>({})

export function isRowExpanded(id: string): boolean {
  return !!expanded()[id]
}

export function toggleRowExpanded(id: string): void {
  setExpanded((prev) => {
    const next = { ...prev }
    if (next[id]) delete next[id]
    else next[id] = true
    return next
  })
}

export function setRowExpanded(id: string, open: boolean): void {
  setExpanded((prev) => {
    const next = { ...prev }
    if (open) next[id] = true
    else delete next[id]
    return next
  })
}

export function clearExpanded(): void {
  setExpanded({})
}
