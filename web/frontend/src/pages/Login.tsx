import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { requestMagicLink } from '../lib/api'

export default function Login() {
  const [email, setEmail] = useState('')
  const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'error'>('idle')
  const [message, setMessage] = useState('')
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
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

  return (
    <div className="max-w-md mx-auto px-6 py-16">
      <h1 className="text-3xl font-bold text-gray-900 mb-2">Log In</h1>
      <p className="text-gray-600 mb-8">Enter your email and we'll send you a magic link.</p>

      {status === 'sent' ? (
        <div className="bg-green-50 border border-green-200 rounded-lg p-6 text-center">
          <div className="text-4xl mb-3">📧</div>
          <p className="text-green-800 font-medium">{message}</p>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
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
          {status === 'error' && (
            <p className="text-red-600 text-sm">{message}</p>
          )}
        </form>
      )}
    </div>
  )
}
