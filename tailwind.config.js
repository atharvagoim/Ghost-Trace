/** @type {import('tailwindcss').Config} */
// Mostly black / grey / white palette with a few status accents. Glass surfaces are white at low alpha over a faint grid backdrop.
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Text"', '"SF Pro Display"', '"Inter Variable"', 'system-ui', 'sans-serif'],
        display: ['-apple-system', 'BlinkMacSystemFont', '"SF Pro Display"', '"Inter Variable"', 'system-ui', 'sans-serif'],
        mono: ['ui-monospace', '"SF Mono"', '"IBM Plex Mono"', 'Menlo', 'monospace'],
      },
      colors: {
        label: { DEFAULT: '#ffffff', 2: 'rgba(255,255,255,0.64)', 3: 'rgba(255,255,255,0.40)', 4: 'rgba(255,255,255,0.20)' },
        fill: { 1: 'rgba(255,255,255,0.18)', 2: 'rgba(255,255,255,0.14)', 3: 'rgba(255,255,255,0.09)', 4: 'rgba(255,255,255,0.06)' },
        sep: 'rgba(255,255,255,0.12)',
        tint: { DEFAULT: '#FFFFFF', light: '#E4E4E4' },
        ios: { red: '#FF5A52', orange: '#FFA726', yellow: '#F2D95C', green: '#3DDC84', teal: '#5CC8FF', indigo: '#BDBDBD', purple: '#8C8C8C', pink: '#F2F2F2' },
        sev: { critical: '#FF5A52', high: '#FFA726', medium: '#F2D95C', low: '#5CC8FF' },
      },
      borderRadius: { sheet: '40px', group: '30px', row: '18px' },
      fontSize: {
        // iOS Dynamic Type (default size), in px
        'large-title': ['32px', { lineHeight: '38px', letterSpacing: '0.37px', fontWeight: '700' }],
        title1: ['26px', { lineHeight: '32px', letterSpacing: '0.36px', fontWeight: '700' }],
        title2: ['21px', { lineHeight: '26px', letterSpacing: '0.35px', fontWeight: '700' }],
        title3: ['18px', { lineHeight: '23px', letterSpacing: '0.38px', fontWeight: '600' }],
        headline: ['16px', { lineHeight: '21px', letterSpacing: '-0.41px', fontWeight: '600' }],
        body: ['16px', { lineHeight: '21px', letterSpacing: '-0.41px' }],
        callout: ['15px', { lineHeight: '20px', letterSpacing: '-0.32px' }],
        subhead: ['14px', { lineHeight: '19px', letterSpacing: '-0.24px' }],
        footnote: ['12.5px', { lineHeight: '17px', letterSpacing: '-0.08px' }],
        caption: ['12px', { lineHeight: '16px', letterSpacing: '0px' }],
        caption2: ['11px', { lineHeight: '13px', letterSpacing: '0.07px' }],
      },
      transitionTimingFunction: { ios: 'cubic-bezier(0.32, 0.72, 0, 1)' },
      keyframes: {
        drift: {
          '0%,100%': { transform: 'translate3d(0,0,0) scale(1)' },
          '50%': { transform: 'translate3d(4%, -3%, 0) scale(1.08)' },
        },
        scan: { '0%': { transform: 'translateY(-100%)' }, '100%': { transform: 'translateY(100vh)' } },
        shimmer: { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
        pulseDot: { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.35 } },
      },
      animation: {
        drift: 'drift 22s ease-in-out infinite',
        'drift-slow': 'drift 30s ease-in-out infinite reverse',
        shimmer: 'shimmer 1.6s linear infinite',
        scan: 'scan 9s linear infinite',
        pulseDot: 'pulseDot 1.4s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
