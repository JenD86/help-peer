import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { requestMagicLink, signup } from '../lib/api'

export default function Login() {
  const [mode, setMode] = useState<'login' | 'signup'>('login')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'error'>('idle')
  const [message, setMessage] = useState('')
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setStatus('sending')
    try {
      const resp = await requestMagicLink(email)
      setStatus('sent')
      setMessage(resp.message || 'Check your email for a login link.')
    } catch (err: any) {
      setStatus('error')
      setMessage(err.message || 'Failed to send login link')
    }
  }

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault()
    setStatus('sending')
    try {
      await signup(username)
      navigate('/upload')
    } catch (err: any) {
      setStatus('error')
      setMessage(err.message || 'Failed to sign up')
    }
  }

  return (
    <div className="max-w-md mx-auto px-6 py-16">
      <div className="flex gap-2 mb-6 border-b border-gray-200">
        <button
          onClick={() => { setMode('login'); setStatus('idle'); setMessage('') }}
          className={`px-4 py-2 font-medium border-b-2 transition ${mode === 'login' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          Log In
        </button>
        <button
          onClick={() => { setMode('signup'); setStatus('idle'); setMessage('') }}
          className={`px-4 py-2 font-medium border-b-2 transition ${mode === 'signup' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          Sign Up
        </button>
      </div>

      {mode === 'login' && status === 'sent' ? (
        <div className="bg-green-50 border border-green-200 rounded-lg p-6 text-center">
          <div className="text-4xl mb-3">📧</div>
          <p className="text-green-800 font-medium">{message}</p>
        </div>
      ) : mode === 'login' ? (
        <>
          <p className="text-gray-600 mb-6">Enter your email and we'll send you a magic link.</p>
          <form onSubmit={handleLogin} className="space-y-4">
            <input
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
            <button
              type="submit"
              disabled={status === 'sending'}
              className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition"
            >
              {status === 'sending' ? 'Sending...' : 'Send Magic Link'}
            </button>
            {status === 'error' && <p className="text-red-600 text-sm">{message}</p>}
          </form>
        </>
      ) : (
        <>
          <p className="text-gray-600 mb-6">Pick a username to create an account. No email needed — you can add one later for notifications.</p>
          <form onSubmit={handleSignup} className="space-y-4">
            <div className="flex items-center border border-gray-300 rounded-lg focus-within:ring-2 focus-within:ring-indigo-500">
              <span className="pl-4 text-gray-400">@</span>
              <input
                type="text"
                placeholder="your-name"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                minLength={3}
                maxLength={30}
                pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*"
                title="3-30 characters: letters, digits, '-' and '_', starting with a letter or digit"
                className="flex-1 px-2 py-3 rounded-lg outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={status === 'sending'}
              className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition"
            >
              {status === 'sending' ? 'Creating...' : 'Create Account'}
            </button>
            {status === 'error' && <p className="text-red-600 text-sm">{message}</p>}
          </form>
        </>
      )}
    </div>
  )
}
