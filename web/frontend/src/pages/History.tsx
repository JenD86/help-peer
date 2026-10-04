import { useEffect, useState } from 'react'
import { getHistory } from '../lib/api'

export default function History() {
  const [transfers, setTransfers] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getHistory()
      .then(data => setTransfers(data.transfers || []))
      .catch(() => setTransfers([]))
      .finally(() => setLoading(false))
  }, [])

  const formatBytes = (b: number) => {
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`
    return `${(b / (1024 * 1024 * 1024)).toFixed(1)} GB`
  }

  if (loading) {
    return <div className="max-w-2xl mx-auto px-6 py-16 text-center text-gray-500">Loading...</div>
  }

  return (
    <div className="max-w-2xl mx-auto px-6 py-8">
      <h1 className="text-3xl font-bold text-gray-900 mb-6">Transfer History</h1>

      {transfers.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          <div className="text-4xl mb-2">📭</div>
          <p>No transfers yet. <a href="/upload" className="text-indigo-600">Send your first file →</a></p>
        </div>
      ) : (
        <div className="space-y-3">
          {transfers.map((t, i) => (
            <div key={i} className="bg-white border border-gray-200 rounded-lg px-4 py-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-900">{t.transfer_name || 'Untitled'}</div>
                  <div className="text-sm text-gray-500">
                    {t.files} file(s) · {formatBytes(t.total_bytes)}
                  </div>
                  {t.message && (
                    <div className="text-sm text-gray-600 whitespace-pre-wrap break-words line-clamp-2">{t.message}</div>
                  )}
                  {t.recipients?.length > 0 && (
                    <div className="text-xs text-gray-400">Sent to {t.recipients.join(', ')}</div>
                  )}
                </div>
                <div className="text-sm text-gray-400">
                  {new Date(t.created_at).toLocaleDateString()}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
