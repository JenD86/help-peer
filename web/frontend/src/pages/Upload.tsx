import { useState, useCallback } from 'react'
import { deriveKeys, relayHash, encryptSegment, generateCode, fileHasher } from '../lib/crypto'
import { uploadSegment, uploadManifest, notifyRecipients, checkAuth, type ShardInfo } from '../lib/api'

const SEGMENT_SIZE = 64 * 1024 * 1024 // 64MB
const MAX_RETRIEVALS = 100

interface ManifestSegment {
  id: string
  original_size: number
  encrypted_size: number
  shards: ShardInfo[]
}

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
  const [status, setStatus] = useState<'idle' | 'encrypting' | 'uploading' | 'notifying' | 'done' | 'error'>('idle')
  const [progress, setProgress] = useState('')
  const [result, setResult] = useState<{ code: string; transferName: string; files: number; totalBytes: number } | null>(null)
  const [errorMsg, setErrorMsg] = useState('')

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const dropped = Array.from(e.dataTransfer.files)
    setFiles(prev => [...prev, ...dropped])
    if (!transferName && dropped.length > 0) {
      setTransferName(dropped[0].name)
    }
  }, [transferName])

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files || [])
    setFiles(prev => [...prev, ...selected])
    if (!transferName && selected.length > 0) {
      setTransferName(selected[0].name)
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
        .split(/[,;\n]/)
        .map(r => r.trim())
        .filter(r => r.length > 0)
      if (recipientList.length > 0 && !(await checkAuth()).authenticated) {
        throw new Error('Log in to email the code to recipients, or leave the recipients field empty.')
      }

      const name = transferName || files[0].name
      const code = generateCode()
      const { kData, kIndex } = await deriveKeys(code)
      const rHash = relayHash(kIndex)

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
          const uploaded = await uploadSegment(encrypted)
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
      const manifest = {
        version: 1,
        transfer_name: name,
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
        maxRetrievals: Math.min(Math.max(recipientList.length, 1), MAX_RETRIEVALS),
        transferName: name,
        files: files.length,
        totalBytes,
      })

      setResult({ code, transferName: name, files: files.length, totalBytes })

      // Notify recipients if provided
      if (recipientList.length > 0 && transfer_id) {
        setStatus('notifying')
        setProgress(`Sending notifications to ${recipientList.length} recipient(s)...`)
        await notifyRecipients(transfer_id, code, recipientList)
      }

      setStatus('done')
      setProgress('')
    } catch (err: any) {
      setStatus('error')
      setProgress('')
      setErrorMsg(err.message || 'Upload failed')
    }
  }

  if (status === 'done' && result) {
    return (
      <div className="max-w-md mx-auto px-6 py-16 text-center">
        <div className="text-5xl mb-4">✅</div>
        <h1 className="text-2xl font-bold text-gray-900 mb-2">Upload Complete!</h1>
        <p className="text-gray-600 mb-6">Share this code with your recipient(s):</p>
        <div className="bg-indigo-50 border-2 border-indigo-200 rounded-lg p-6 mb-6">
          <code className="text-2xl font-mono font-bold text-indigo-700">{result.code}</code>
        </div>
        <div className="text-sm text-gray-500 mb-4">
          {result.files} file(s) · {formatBytes(result.totalBytes)}
        </div>
        <button
          onClick={() => {
            setStatus('idle')
            setResult(null)
            setFiles([])
            setRecipients('')
          }}
          className="text-indigo-600 hover:text-indigo-700 font-medium"
        >
          Send more files →
        </button>
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
        <input
          id="file-input"
          type="file"
          multiple
          onChange={handleFileInput}
          className="hidden"
        />
      </div>

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

      {/* Recipients */}
      <textarea
        placeholder="Recipient emails (comma-separated, optional)"
        value={recipients}
        onChange={(e) => setRecipients(e.target.value)}
        rows={2}
        className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-1 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
      />
      <p className="text-xs text-gray-500 mb-4">
        Requires login. The code is emailed through this server, so the server and the recipients' mail
        providers can see it. For the strongest privacy, leave this empty and share the code yourself.
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
