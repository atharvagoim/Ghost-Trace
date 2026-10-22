import { ArcElement, BarElement, CategoryScale, Chart as ChartJS, Legend, LinearScale, Tooltip } from 'chart.js'

// Only what the dashboard's bar and doughnut charts use, so the rest of Chart.js is tree-shaken away.
ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend)
ChartJS.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Inter Variable", system-ui, sans-serif'
ChartJS.defaults.font.size = 12
ChartJS.defaults.color = 'rgba(235,235,245,0.45)'
ChartJS.defaults.borderColor = 'rgba(255,255,255,0.06)'

export const SEV_COLORS = { critical: '#FF5A52', high: '#FFA726', medium: '#F2D95C', low: '#5CC8FF' }
export const SERIES = ['#5CC8FF', '#BDBDBD', '#FFA726', '#F2F2F2', '#3DDC84', '#8C8C8C', '#F2D95C', '#FF5A52', '#6E6E6E', '#E0E0E0']

export const tooltip = {
  backgroundColor: '#1e1e1e',
  borderWidth: 0,
  titleColor: '#fff',
  bodyColor: 'rgba(235,235,245,0.8)',
  padding: 10,
  cornerRadius: 12,
  boxPadding: 4,
  usePointStyle: true,
}
