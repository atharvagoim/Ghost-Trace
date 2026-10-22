import { useEffect, useRef } from 'react'
import { animate, useReducedMotion } from 'motion/react'

const nf = new Intl.NumberFormat()

export default function CountUp({ to = 0, duration = 1.1, className }) {
  const ref = useRef(null)
  const reduce = useReducedMotion()
  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    if (reduce) { el.textContent = nf.format(to); return undefined }
    const controls = animate(0, to, { duration, ease: [0.16, 1, 0.3, 1], onUpdate: (v) => { el.textContent = nf.format(Math.round(v)) } })
    return () => controls.stop()
  }, [to, duration, reduce])
  return <span ref={ref} className={className}>{nf.format(to)}</span>
}
