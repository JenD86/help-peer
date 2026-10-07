import { useEffect, useState } from 'react'
import { Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom'
import Landing from './pages/Landing'
import Login from './pages/Login'
import Verify from './pages/Verify'
import Upload from './pages/Upload'
import Download from './pages/Download'
import History from './pages/History'
import Inbox from './pages/Inbox'
import Account from './pages/Account'
import { checkAuth, logout } from './lib/api'
import ConsentBanner from './components/ConsentBanner'

function NavBar() {
  const location = useLocation()
  const navigate = useNavigate()
  const [user, setUser] = useState<{ email?: string; username?: string } | null>(null)

  // Re-check on navigation so logging in/out (or setting a username) shows up.
  useEffect(() => {
    checkAuth()
      .then(a => setUser(a.authenticated ? a : null))
      .catch(() => setUser(null))
  }, [location.pathname])

  const handleLogout = async () => {
    await logout().catch(() => {})
    setUser(null)
    navigate('/')
  }

  const link = 'text-sm text-gray-600 hover:text-indigo-600'
  return (
    <nav className="bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between">
      <Link to="/" className="text-xl font-bold text-indigo-600">Help Peer</Link>
      <div className="flex gap-4 items-center">
        <Link to="/upload" className={link}>Send</Link>
        <Link to="/download" className={link}>Receive</Link>
        {user ? (
          <>
            <Link to="/inbox" className={link}>Inbox</Link>
            <Link to="/history" className={link}>History</Link>
            <Link to="/account" className={link}>{user.username ? `@${user.username}` : 'Account'}</Link>
            <button onClick={handleLogout} className={link}>Log out</button>
          </>
        ) : (
          <Link to="/login" className={link}>Login</Link>
        )}
      </div>
    </nav>
  )
}

const TITLES: Record<string, string> = {
  '/upload': 'Send Files',
  '/download': 'Receive Files',
  '/login': 'Log In',
  '/verify': 'Logging In',
  '/history': 'Transfer History',
  '/inbox': 'Inbox',
  '/account': 'Account',
}

export default function App() {
  const { pathname } = useLocation()
  useEffect(() => {
    const title = TITLES[pathname]
    document.title = title ? `${title} — Help Peer` : 'Help Peer — Send & Receive Files'
  }, [pathname])

  return (
    <div className="min-h-screen flex flex-col">
      <NavBar />
      <main className="flex-1">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/verify" element={<Verify />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/download" element={<Download />} />
          <Route path="/history" element={<History />} />
          <Route path="/inbox" element={<Inbox />} />
          <Route path="/account" element={<Account />} />
        </Routes>
      </main>
      <footer className="bg-white border-t border-gray-200 px-6 py-4 text-center text-sm text-gray-400">
        Help Peer — End-to-end encrypted file transfer ·{' '}
        <button onClick={() => window.dispatchEvent(new Event('open-consent'))} className="hover:text-gray-600 underline">
          Cookie settings
        </button>
      </footer>
      <ConsentBanner />
    </div>
  )
}
