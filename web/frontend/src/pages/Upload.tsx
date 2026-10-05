import { useState, useCallback, useEffect } from 'react'
import { deriveKeys, relayHash, encryptSegment, generateCode, fileHasher, newSecret, secretHash } from '../lib/crypto'
import {
  uploadSegment, uploadManifest, notifyRecipients, checkAuth, cancelTransfer, searchUsers, lookupUser,
  type ShardInfo, type CancelInfo,
} from '../lib/api'

const SEGMENT_SIZE = 64 * 1024 * 1024 // 64MB
const MAX_RETRIEVALS = 100
const MAX_MESSAGE_CHARS = 2000

const BLOCKED_MEDIA_EXTENSIONS = [
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'tiff', 'tif',
  'ico', 'heic', 'heif', 'avif', 'raw', 'cr2', 'nef', 'arw', 'psd',
  'mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v', 'mpg',
  'mpeg', '3gp', 'ts', 'vob', 'ogv',
  'mp3', 'wav', 'flac', 'aac', 'ogg', 'oga', 'wma', 'm4a', 'alac',
  'aiff', 'aif', 'opus', 'ac3', 'amr', 'au',
]
const BLOCKED_MEDIA_TYPES = /^(image|video|audio)\//

function isBlockedMedia(file: File): boolean {
  if (BLOCKED_MEDIA_TYPES.test(file.type)) return true
  const ext = file.name.includes('.') ? file.name.split('.').pop()!.toLowerCase() : ''
  return BLOCKED_MEDIA_EXTENSIONS.includes(ext)
}

interface ManifestSegment {
  id: string
  original_size: number
  encrypted_size: number
  shards: ShardInfo[]
}

// A recipient is an email address if it has an '@' after the first
// character; otherwise it's a username ("alice" or "@alice").
const isEmail = (r: string) => r.indexOf('@') > 0

// Make a browser file name safe and unique as a manifest path. Receivers
// reject '\', ':' and NUL in paths, and duplicate paths would overwrite each other.
function manifestPath(name: string, used: Set<string>): string {
  const base = name.replace(/[\\:\0/]/g, '_') || 'file'
  let path = base
  for (let n = 2; used.has(path); n++) {
    const dot = base.lastIndexOf('.')
    path = dot > 0 ? `${base.slice(0, dot)} (${n})${base.slice(dot)}` : `${base} (${n})`
  }
  used.add(path)
  return path
}

export default function Upload() {
  const [files, setFiles] = useState<File[]>([])
  const [transferName, setTransferName] = useState('')
  const [recipients, setRecipients] = useState('')
  const [message, setMessage] = useState('')
  const [userQuery, setUserQuery] = useState('')
  const [userResults, setUserResults] = useState<string[]>([])

  // Directory search (listed users only; needs 3+ characters and a login)
  useEffect(() => {
    const q = userQuery.trim().replace(/^@/, '')
    if (q.length < 3) {
      setUserResults([])
      return
    }
    const timer = setTimeout(() => {
      searchUsers(q).then(setUserResults).catch(() => setUserResults([]))
    }, 250)
    return () => clearTimeout(timer)
  }, [userQuery])

  const addRecipient = (username: string) => {
    setRecipients(prev => {
      const list = prev.split(/[,;\s]+/).filter(Boolean)
      return list.includes(`@${username}`) ? prev : [...list, `@${username}`].join(', ')
    })
    setUserQuery('')
    setUserResults([])
  }
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'uploading' | 'notifying' | 'done' | 'error'>('idle')
  const [progress, setProgress] = useState('')
  const [result, setResult] = useState<{ code: string; transferName: string; files: number; totalBytes: number } | null>(null)
  // What's needed to cancel the transfer just sent (kept only in this page)
  const [cancelInfo, setCancelInfo] = useState<CancelInfo | null>(null)
  const [cancelState, setCancelState] = useState<'idle' | 'cancelling' | 'cancelled' | 'error'>('idle')
  const [cancelMsg, setCancelMsg] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [mediaWarning, setMediaWarning] = useState('')

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const dropped = Array.from(e.dataTransfer.files)
    const allowed = dropped.filter(f => !isBlockedMedia(f))
    const rejected = dropped.filter(f => isBlockedMedia(f))
    if (rejected.length > 0) {
      setMediaWarning(`Rejected ${rejected.length} media file(s): ${rejected.map(f => f.name).join(', ')}. Images, video and audio are not allowed.`)
    } else {
      setMediaWarning('')
    }
    setFiles(prev => [...prev, ...allowed])
    if (!transferName && allowed.length > 0) {
      setTransferName(allowed[0].name)
    }
  }, [transferName])

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files || [])
    const allowed = selected.filter(f => !isBlockedMedia(f))
    const rejected = selected.filter(f => isBlockedMedia(f))
    if (rejected.length > 0) {
      setMediaWarning(`Rejected ${rejected.length} media file(s): ${rejected.map(f => f.name).join(', ')}. Images, video and audio are not allowed.`)
    } else {
      setMediaWarning('')
    }
    setFiles(prev => [...prev, ...allowed])
    if (!transferName && allowed.length > 0) {
      setTransferName(allowed[0].name)
    }
  }

  const removeFile = (idx: number) => {
    setFiles(prev => prev.filter((_, i) => i !== idx))
  }

  const formatBytes = (b: number) => {
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`
    return `${(b / (1024 * 1024 * 1024)).toFixed(1)} GB`
  }

  const totalBytes = files.reduce((sum, f) => sum + f.size, 0)

  const handleUpload = async () => {
    if (files.length === 0) return
    setStatus('encrypting')
    setProgress('Generating transfer code...')
    setErrorMsg('')

    try {
      const recipientList = recipients
        .split(/[,;\s]+/)
        .map(r => r.trim())
        .filter(r => r.length > 0)
      if (recipientList.length > 0) {
        if (!(await checkAuth()).authenticated) {
          throw new Error('Log in to send to recipients, or leave the recipients field empty.')
        }
        // Catch unknown usernames before uploading anything.
        const usernames = recipientList.filter(r => !isEmail(r))
        const exists = await Promise.all(usernames.map(u => lookupUser(u)))
        const unknown = usernames.filter((_, i) => !exists[i])
        if (unknown.length > 0) {
          throw new Error(`Unknown username(s): ${unknown.join(', ')}`)
        }
      }

      const name = transferName || files[0].name
      const code = generateCode()
      const { kData, kIndex } = await deriveKeys(code)
      const rHash = relayHash(kIndex)
      const ackSecret = newSecret()
      const deleteToken = newSecret()
      const deleteTokenHash = secretHash(deleteToken)

      // Encrypt and upload each file one 64MB segment at a time, so files
      // never have to fit in memory whole.
      const usedPaths = new Set<string>()
      const manifestFiles = []
      let doneBytes = 0
      for (const file of files) {
        const hasher = fileHasher()
        const segments: ManifestSegment[] = []

        for (let offset = 0, i = 0; offset < file.size; offset += SEGMENT_SIZE, i++) {
          const pct = totalBytes ? Math.floor((doneBytes / totalBytes) * 100) : 0
          setStatus('encrypting')
          setProgress(`Encrypting ${file.name} (${pct}% overall)...`)
          const plaintext = await file.slice(offset, offset + SEGMENT_SIZE).arrayBuffer()
          hasher.update(plaintext)
          const encrypted = await encryptSegment(kData, plaintext)

          setStatus('uploading')
          setProgress(`Uploading ${file.name} (${pct}% overall)...`)
          const uploaded = await uploadSegment(encrypted, deleteTokenHash)
          segments.push({
            id: `seg_${String(i).padStart(6, '0')}`,
            original_size: plaintext.byteLength,
            encrypted_size: uploaded.encrypted_size,
            shards: uploaded.shards,
          })
          doneBytes += plaintext.byteLength
        }

        manifestFiles.push({
          path: manifestPath(file.name, usedPaths),
          size: file.size,
          blake3: hasher.hexdigest(),
          segments,
        })
      }

      // Build and encrypt the manifest (same format as the CLI)
      setProgress('Uploading manifest...')
      const note = message.trim()
      const manifest = {
        version: 2,
        transfer_name: name,
        ...(note ? { message: note } : {}),
        ack_secret: ackSecret,
        delete_token: deleteToken,
        total_bytes: totalBytes,
        segment_size: SEGMENT_SIZE,
        erasure_data_shards: 8,
        erasure_parity_shards: 4,
        files: manifestFiles,
      }
      const manifestJson = new TextEncoder().encode(JSON.stringify(manifest))
      const encryptedManifest = await encryptSegment(kData, manifestJson.buffer as ArrayBuffer)

      const { transfer_id } = await uploadManifest({
        manifestHash: rHash,
        manifestData: encryptedManifest,
        ackHash: secretHash(ackSecret),
        message: note,
        maxRetrievals: Math.min(Math.max(recipientList.length, 1), MAX_RETRIEVALS),
        transferName: name,
        files: files.length,
        totalBytes,
      })

      setResult({ code, transferName: name, files: files.length, totalBytes })
      setCancelInfo({
        manifestHash: rHash,
        ackSecret,
        deleteToken,
        shards: manifestFiles.flatMap(f => f.segments.flatMap(s => s.shards.map(sh => ({ hash: sh.hash, node: sh.node })))),
      })
      setCancelState('idle')

      // Notify recipients if provided
      if (recipientList.length > 0 && transfer_id) {
        setStatus('notifying')
        setProgress(`Sending notifications to ${recipientList.length} recipient(s)...`)
        await notifyRecipients(transfer_id, rHash, code, recipientList)
      }

      setStatus('done')
      setProgress('')
    } catch (err: any) {
      setStatus('error')
      setProgress('')
      setErrorMsg(err.message || 'Upload failed')
    }
  }

  const handleCancel = async () => {
    if (!cancelInfo) return
    if (!window.confirm('Cancel this transfer? Recipients will no longer be able to download it.')) return
    setCancelState('cancelling')
    try {
      const r = await cancelTransfer(cancelInfo)
      setCancelState('cancelled')
      setCancelMsg(
        r.shards_failed > 0
          ? `Transfer cancelled. ${r.shards_failed} stored piece(s) couldn't be deleted right away and will expire within 24 hours.`
          : 'Transfer cancelled and all stored data deleted.'
      )
    } catch (err: any) {
      setCancelState('error')
      setCancelMsg(err.message || 'Cancel failed')
    }
  }

  if (status === 'done' && result) {
    return (
      <div className="max-w-md mx-auto px-6 py-16 text-center">
        <div className="text-5xl mb-4">✅</div>
        <h1 className="text-2xl font-bold text-gray-900 mb-2">Upload Complete!</h1>
        <p className="text-gray-600 mb-6">Share this code with your recipient(s):</p>
        <div className={`border-2 rounded-lg p-6 mb-6 ${cancelState === 'cancelled' ? 'bg-gray-50 border-gray-200' : 'bg-indigo-50 border-indigo-200'}`}>
          <code className={`text-2xl font-mono font-bold ${cancelState === 'cancelled' ? 'text-gray-400 line-through' : 'text-indigo-700'}`}>
            {result.code}
          </code>
        </div>
        <div className="text-sm text-gray-500 mb-4">
          {result.files} file(s) · {formatBytes(result.totalBytes)}
        </div>
        {cancelMsg && (
          <p className={`text-sm mb-4 ${cancelState === 'error' ? 'text-red-600' : 'text-gray-600'}`}>{cancelMsg}</p>
        )}
        <div className="flex justify-center gap-6">
          {cancelState !== 'cancelled' && (
            <button
              onClick={handleCancel}
              disabled={cancelState === 'cancelling'}
              className="text-red-500 hover:text-red-700 font-medium disabled:opacity-50"
            >
              {cancelState === 'cancelling' ? 'Cancelling...' : 'Cancel transfer'}
            </button>
          )}
          <button
            onClick={() => {
              setStatus('idle')
              setResult(null)
              setCancelInfo(null)
              setCancelMsg('')
              setFiles([])
              setRecipients('')
              setMessage('')
            }}
            className="text-indigo-600 hover:text-indigo-700 font-medium"
          >
            Send more files →
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-2xl mx-auto px-6 py-8">
      <h1 className="text-3xl font-bold text-gray-900 mb-6">Send Files</h1>

      {/* Drop zone */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        onClick={() => document.getElementById('file-input')?.click()}
        className="border-2 border-dashed border-gray-300 rounded-xl p-12 text-center cursor-pointer hover:border-indigo-400 hover:bg-indigo-50/30 transition mb-4"
      >
        <div className="text-4xl mb-2">📁</div>
        <p className="text-gray-600">Drag & drop files here, or click to select</p>
        <p className="text-xs text-gray-400 mt-1">Images, video and audio files are not accepted</p>
        <input
          id="file-input"
          type="file"
          multiple
          onChange={handleFileInput}
          className="hidden"
        />
      </div>

      {mediaWarning && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-sm text-amber-800 mb-4">
          {mediaWarning}
        </div>
      )}

      {/* File list */}
      {files.length > 0 && (
        <div className="space-y-2 mb-4">
          {files.map((f, i) => (
            <div key={i} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-2">
              <span className="text-sm text-gray-700 truncate flex-1">{f.name}</span>
              <span className="text-xs text-gray-400 ml-2">{formatBytes(f.size)}</span>
              <button onClick={() => removeFile(i)} className="text-red-400 hover:text-red-600 ml-2 text-sm">✕</button>
            </div>
          ))}
          <div className="text-sm text-gray-500 text-right">Total: {formatBytes(totalBytes)}</div>
        </div>
      )}

      {/* Transfer name */}
      <input
        type="text"
        placeholder="Transfer name (optional)"
        value={transferName}
        onChange={(e) => setTransferName(e.target.value)}
        className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-4 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
      />

      {/* Message */}
      <textarea
        placeholder="Message to recipients (optional): what's in this transfer, how to use it..."
        value={message}
        onChange={(e) => setMessage(e.target.value.slice(0, MAX_MESSAGE_CHARS))}
        rows={3}
        className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-1 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
      />
      <p className="text-xs text-gray-500 mb-4 flex justify-between">
        <span>Shown to recipients with the files, in their inbox and in notification emails.</span>
        <span>{message.length}/{MAX_MESSAGE_CHARS}</span>
      </p>

      {/* Recipients */}
      <textarea
        placeholder="Recipients (optional): @usernames and/or emails, comma-separated"
        value={recipients}
        onChange={(e) => setRecipients(e.target.value)}
        rows={2}
        className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
      />
      <div className="relative mb-1">
        <input
          type="text"
          value={userQuery}
          onChange={(e) => setUserQuery(e.target.value)}
          placeholder="Find a person by username..."
          className="w-full px-4 py-2 text-sm border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
        />
        {userResults.length > 0 && (
          <div className="absolute z-10 w-full bg-white border border-gray-200 rounded-lg mt-1 shadow">
            {userResults.map(u => (
              <button
                key={u}
                type="button"
                onClick={() => addRecipient(u)}
                className="block w-full text-left px-4 py-2 text-sm hover:bg-indigo-50"
              >
                @{u}
              </button>
            ))}
          </div>
        )}
      </div>
      <p className="text-xs text-gray-500 mb-4">
        Requires login. Usernames get the transfer in their Help Peer inbox plus an email alert; email addresses get
        the code by email. Either way the code passes through this server (and, for email, the recipients' mail
        providers). For the strongest privacy, leave this empty and share the code yourself.
      </p>

      {/* Upload button */}
      <button
        onClick={handleUpload}
        disabled={files.length === 0 || status === 'encrypting' || status === 'uploading' || status === 'notifying'}
        className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition mb-4"
      >
        {status === 'encrypting' ? 'Encrypting...' :
         status === 'uploading' ? 'Uploading...' :
         status === 'notifying' ? 'Sending notifications...' :
         'Encrypt & Upload'}
      </button>

      {/* Progress */}
      {progress && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-700">
          {progress}
        </div>
      )}

      {/* Error */}
      {status === 'error' && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700 mt-4">
          {errorMsg}
        </div>
      )}
    </div>
  )
}
