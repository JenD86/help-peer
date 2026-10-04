import { Routes, Route, Link, useLocation } from 'react-router-dom'
import Landing from './pages/Landing'
import Login from './pages/Login'
import Verify from './pages/Verify'
import Upload from './pages/Upload'
import Download from './pages/Download'
import History from './pages/History'

function NavBar() {
  const location = useLocation()
  const isLanding = location.pathname === '/'

  return (
    <nav className="bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between">
      <Link to="/" className="text-xl font-bold text-indigo-600">Help Peer</Link>
      <div className="flex gap-4 items-center">
        <Link to="/upload" className="text-sm text-gray-600 hover:text-indigo-600">Send</Link>
        <Link to="/download" className="text-sm text-gray-600 hover:text-indigo-600">Receive</Link>
        <Link to="/login" className="text-sm text-gray-600 hover:text-indigo-600">Login</Link>
      </div>
    </nav>
  )
}

export default function App() {
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
        </Routes>
      </main>
      <footer className="bg-white border-t border-gray-200 px-6 py-4 text-center text-sm text-gray-400">
        Help Peer — End-to-end encrypted file transfer
      </footer>
    </div>
  )
}
