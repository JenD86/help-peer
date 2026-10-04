import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { verifyMagicLink } from '../lib/api'

export default function Verify() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying')
  const [message, setMessage] = useState('')

  useEffect(() => {
    const token = searchParams.get('token')
    if (!token) {
      setStatus('error')
      setMessage('No token provided')
      return
    }

    verifyMagicLink(token)
      .then(() => {
        setStatus('success')
        setTimeout(() => navigate('/upload'), 1500)
      })
      .catch((err) => {
        setStatus('error')
        setMessage(err.message || 'Invalid or expired link')
      })
  }, [])

  return (
    <div className="max-w-md mx-auto px-6 py-16 text-center">
      {status === 'verifying' && (
        <>
          <div className="animate-spin inline-block w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full mb-4"></div>
          <p className="text-gray-600">Verifying your login link...</p>
        </>
      )}
      {status === 'success' && (
        <>
          <div className="text-4xl mb-3">✅</div>
          <p className="text-green-700 font-medium">Logged in! Redirecting...</p>
        </>
      )}
      {status === 'error' && (
        <>
          <div className="text-4xl mb-3">❌</div>
          <p className="text-red-600">{message}</p>
        </>
      )}
    </div>
  )
}
