// Faint perspective grid, soft white glows and a slow scanline behind every glass surface. Black, grey and white.
export default function Ambient({ intensity = 1 }) {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-black">
      <div className="absolute inset-0"
        style={{
          opacity: 0.5 * intensity,
          backgroundImage: 'linear-gradient(rgba(255,255,255,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.07) 1px, transparent 1px)',
          backgroundSize: '56px 56px',
          maskImage: 'radial-gradient(ellipse 80% 70% at 50% 30%, #000 20%, transparent 75%)',
          WebkitMaskImage: 'radial-gradient(ellipse 80% 70% at 50% 30%, #000 20%, transparent 75%)',
        }} />
      <div className="absolute -left-[15%] -top-[25%] h-[60vmax] w-[60vmax] animate-drift rounded-full blur-[120px]"
        style={{ background: 'radial-gradient(circle, rgba(255,255,255,0.5), transparent 60%)', opacity: 0.06 * intensity }} />
      <div className="absolute -bottom-[30%] -right-[15%] h-[55vmax] w-[55vmax] animate-drift-slow rounded-full blur-[140px]"
        style={{ background: 'radial-gradient(circle, rgba(200,200,200,0.5), transparent 60%)', opacity: 0.05 * intensity }} />
      <div className="absolute inset-x-0 top-0 h-px animate-scan bg-gradient-to-r from-transparent via-white/20 to-transparent" style={{ opacity: intensity }} />
      <div className="absolute inset-0" style={{ background: 'radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.7) 100%)' }} />
    </div>
  )
}
