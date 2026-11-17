import { createMemo } from 'solid-js'

type Props = {
  values: number[]
  width?: number
  height?: number
  class?: string
}

export function Sparkline(props: Props) {
  const w = () => props.width ?? 160
  const h = () => props.height ?? 40

  const path = createMemo(() => {
    const vals = props.values
    if (!vals.length) return ''
    const min = Math.min(...vals)
    const max = Math.max(...vals)
    const span = max - min || 1
    return vals
      .map((v, i) => {
        const x = (i / Math.max(vals.length - 1, 1)) * (w() - 2) + 1
        const y = h() - 2 - ((v - min) / span) * (h() - 4)
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`
      })
      .join(' ')
  })

  return (
    <svg
      class={props.class ?? 'sparkline'}
      width={w()}
      height={h()}
      viewBox={`0 0 ${w()} ${h()}`}
      aria-hidden="true"
    >
      <path d={path()} fill="none" stroke="currentColor" stroke-width="1.75" />
    </svg>
  )
}
