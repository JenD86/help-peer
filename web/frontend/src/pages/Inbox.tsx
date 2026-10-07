import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { getInbox, dismissInboxItem, type InboxItem } from '../lib/api'

const formatBytes = (b: number) => {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`
  return `${(b / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

const timeLeft = (iso: string) => {
  const hours = Math.max(0, (new Date(iso).getTime() - Date.now()) / 3_600_000)
  return hours >= 1 ? `${Math.floor(hours)}h left` : `${Math.max(1, Math.floor(hours * 60))}m left`
}

export default function Inbox() {
  const navigate = useNavigate()
  const [items, setItems] = useState<InboxItem[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getInbox()
      .then(setItems)
      .catch(err => setError(err.message || 'Could not load your inbox'))
  }, [])

  const dismiss = async (id: string) => {
    await dismissInboxItem(id).catch(() => {})
    setItems(prev => (prev ?? []).filter(i => i.id !== id))
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto px-6 py-16 text-center text-gray-600">
        {error.includes('authentication') ? (
          <p><Link to="/login" className="text-indigo-600">Log in</Link> to see transfers sent to you.</p>
        ) : (
          <p className="text-red-600">{error}</p>
        )}
      </div>
    )
  }
  if (items === null) {
    return <div className="max-w-2xl mx-auto px-6 py-16 text-center text-gray-500">Loading...</div>
  }

  return (
    <div className="max-w-2xl mx-auto px-6 py-8">
      <h1 className="text-3xl font-bold text-gray-900 mb-2">Inbox</h1>
      <p className="text-sm text-gray-500 mb-6">
        Transfers sent to your username. Each one disappears once you receive it, or after 24 hours.
      </p>

      {items.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          <div className="text-4xl mb-2">📭</div>
          <p>Nothing waiting for you.</p>
          <p className="text-sm mt-2">
            Others can send to you by username — <Link to="/account" className="text-indigo-600">set yours up</Link>.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {items.map(item => (
            <div key={item.id} className="bg-white border border-gray-200 rounded-lg px-4 py-3">
              <div className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="font-medium text-gray-900 truncate">{item.transfer_name || 'Untitled'}</div>
                  <div className="text-sm text-gray-500">
                    From {item.sender_username ? `@${item.sender_username}` : item.sender_email} ·{' '}
                    {item.files} file(s) · {formatBytes(item.total_bytes)} · {timeLeft(item.expires_at)}
                  </div>
                  {item.message && (
                    <p className="text-sm text-gray-700 whitespace-pre-wrap break-words border-l-2 border-indigo-200 pl-2 my-1">
                      {item.message}
                    </p>
                  )}
                  <code className="text-xs text-gray-400 font-mono">{item.code}</code>
                </div>
                <div className="flex gap-3 shrink-0">
                  <button
                    onClick={() => navigate('/download', { state: { code: item.code } })}
                    className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-indigo-700"
                  >
                    Receive
                  </button>
                  <button onClick={() => dismiss(item.id)} className="text-sm text-gray-400 hover:text-gray-600">
                    Dismiss
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
