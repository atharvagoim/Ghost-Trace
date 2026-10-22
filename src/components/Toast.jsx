import { createContext, useCallback, useContext, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { CheckCircle2, AlertCircle } from 'lucide-react'
import clsx from 'clsx'
import { spring } from './ui'

const ToastContext = createContext(() => {})
const ConfirmContext = createContext(async () => false)

/** Toasts drop in from the top as a small glass capsule, like an iOS system banner.
 *  confirm() shows an iOS-style alert and resolves to true/false, replacing window.confirm. */
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const [dialog, setDialog] = useState(null)
  const resolver = useRef(null)

  const push = useCallback((message, type = 'success') => {
    const id = Math.random().toString(36).slice(2)
    setToasts((t) => [...t.slice(-2), { id, message, type }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3800)
  }, [])

  const confirm = useCallback((opts) => new Promise((resolve) => {
    resolver.current = resolve
    setDialog(opts)
  }), [])

  const close = (answer) => {
    resolver.current?.(answer)
    resolver.current = null
    setDialog(null)
  }

  return (
    <ToastContext.Provider value={push}>
      <ConfirmContext.Provider value={confirm}>
        {children}
        <div className="pointer-events-none fixed inset-x-0 top-[max(12px,env(safe-area-inset-top))] z-[60] flex flex-col items-center gap-2 px-4" aria-live="polite">
          <AnimatePresence>
            {toasts.map((t) => (
              <motion.div key={t.id} layout initial={{ y: -40, opacity: 0, scale: 0.9 }} animate={{ y: 0, opacity: 1, scale: 1 }}
                exit={{ y: -20, opacity: 0, scale: 0.95 }} transition={spring}
                onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}
                className="glass-thick pointer-events-auto flex max-w-md cursor-pointer items-center gap-2.5 rounded-full py-2.5 pl-3 pr-5 text-subhead text-label">
                {t.type === 'error'
                  ? <AlertCircle className="h-5 w-5 shrink-0 text-ios-red" />
                  : <CheckCircle2 className="h-5 w-5 shrink-0 text-ios-green" />}
                <span>{t.message}</span>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        <AnimatePresence>
          {dialog && (
            <div className="fixed inset-0 z-[70] flex items-center justify-center p-6" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
              <motion.div className="absolute inset-0 bg-black/45" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => close(false)} />
              <motion.div initial={{ scale: 1.12, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.96, opacity: 0 }} transition={{ ...spring, stiffness: 500 }}
                className="glass-thick relative w-full max-w-[290px] overflow-hidden rounded-[16px] text-center">
                <div className="px-4 pb-4 pt-5">
                  <h2 id="confirm-title" className="text-headline text-label">{dialog.title}</h2>
                  {dialog.message && <p className="mt-1 text-footnote text-label-2">{dialog.message}</p>}
                </div>
                <div className="hairline-t grid grid-cols-2">
                  <button autoFocus onClick={() => close(false)} className="h-11 text-body text-tint-light transition-colors active:bg-white/10">Cancel</button>
                  <button onClick={() => close(true)}
                    className={clsx('relative h-11 text-body font-semibold transition-colors active:bg-white/10 before:absolute before:inset-y-0 before:left-0 before:w-px before:scale-x-50 before:bg-sep',
                      dialog.destructive ? 'text-ios-red' : 'text-tint-light')}>
                    {dialog.confirmLabel || 'OK'}
                  </button>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>
      </ConfirmContext.Provider>
    </ToastContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useToast = () => useContext(ToastContext)
// eslint-disable-next-line react-refresh/only-export-components
export const useConfirm = () => useContext(ConfirmContext)
