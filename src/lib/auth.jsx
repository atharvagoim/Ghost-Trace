import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api, tokenStore } from './api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(Boolean(tokenStore.get()))

  useEffect(() => {
    if (!tokenStore.get()) return
    api('/api/auth/me')
      .then(setUser)
      .catch(() => tokenStore.clear())
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const onLogout = () => setUser(null)
    window.addEventListener('ghosttrace:logout', onLogout)
    return () => window.removeEventListener('ghosttrace:logout', onLogout)
  }, [])

  const handleToken = useCallback((data) => {
    tokenStore.set(data.access_token)
    setUser(data.user)
    return data.user
  }, [])

  const login = useCallback((email, password) =>
    api('/api/auth/login', { method: 'POST', body: { email, password } }).then(handleToken), [handleToken])

  const register = useCallback((payload) =>
    api('/api/auth/register', { method: 'POST', body: payload }).then(handleToken), [handleToken])

  const logout = useCallback(() => {
    tokenStore.clear()
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider value={{ user, setUser, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => useContext(AuthContext)
