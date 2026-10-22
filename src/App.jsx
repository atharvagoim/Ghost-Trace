import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useAuth } from './lib/auth'
import AppLayout from './components/AppLayout'
import Ambient from './components/Ambient'
import { Spinner } from './components/ui'

const Landing = lazy(() => import('./pages/Landing'))
const Login = lazy(() => import('./pages/Login'))
const Register = lazy(() => import('./pages/Register'))
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'))
const ResetPassword = lazy(() => import('./pages/ResetPassword'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Scans = lazy(() => import('./pages/Scans'))
const ScanDetail = lazy(() => import('./pages/ScanDetail'))
const Findings = lazy(() => import('./pages/Findings'))
const Breach = lazy(() => import('./pages/Breach'))
const Monitors = lazy(() => import('./pages/Monitors'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Settings = lazy(() => import('./pages/Settings'))
const NotFound = lazy(() => import('./pages/NotFound'))

function FullScreenLoader() {
  return <div className="flex min-h-dvh items-center justify-center"><Spinner className="h-7 w-7" /></div>
}

function RequireAuth({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()
  if (loading) return <FullScreenLoader />
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return children
}

function GuestOnly({ children }) {
  const { user, loading } = useAuth()
  if (loading) return null
  return user ? <Navigate to="/app" replace /> : children
}

export default function App() {
  return (
    <>
      <Ambient />
      <Suspense fallback={<FullScreenLoader />}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<GuestOnly><Login /></GuestOnly>} />
          <Route path="/register" element={<GuestOnly><Register /></GuestOnly>} />
          <Route path="/forgot-password" element={<GuestOnly><ForgotPassword /></GuestOnly>} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/app" element={<RequireAuth><AppLayout /></RequireAuth>}>
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="findings" element={<Findings />} />
            <Route path="breach" element={<Breach />} />
            <Route path="monitors" element={<Monitors />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </>
  )
}
