import { useState, useCallback } from 'react'
import { deriveKeys, relayHash, encryptSegment, generateCode, bufToBase64 } from '../lib/crypto'
import { uploadTransfer, notifyRecipients, type UploadFile, type UploadResult } from '../lib/api'

const SEGMENT_SIZE = 64 * 1024 * 1024 // 64MB

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
      const code = generateCode()
      const { kData, kIndex } = await deriveKeys(code)
      const rHash = await relayHash(kIndex)

      // Encrypt each file
      const uploadFiles: UploadFile[] = []
      for (let i = 0; i < files.length; i++) {
        const file = files[i]
        setProgress(`Encrypting ${file.name}...`)

        // For files larger than SEGMENT_SIZE, we'd chunk — but for web, encrypt whole file
        // (backend handles erasure coding on the encrypted blob)
        const data = await file.arrayBuffer()
        const encrypted = await encryptSegment(kData, data)
        uploadFiles.push({
          path: file.name,
          size: file.size,
          data: encrypted,
        })
      }

      // Build manifest (encrypted by browser, sent to backend which uploads to relay)
      setProgress('Building manifest...')
      const manifest = {
        version: 1,
        transfer_name: transferName || files[0].name,
        total_bytes: totalBytes,
        segment_size: SEGMENT_SIZE,
        erasure_data_shards: 8,
        erasure_parity_shards: 4,
        files: uploadFiles.map(f => ({
          path: f.path,
          size: f.size,
          segments: [{
            id: 'seg_000000',
            encrypted_size: f.data.byteLength,
            shards: [],
          }],
        })),
      }

      const manifestJson = new TextEncoder().encode(JSON.stringify(manifest)).buffer as ArrayBuffer
      const encryptedManifest = await encryptSegment(kData, manifestJson)

      // Parse recipients
      const recipientList = recipients
        .split(/[,;\n]/)
        .map(r => r.trim())
        .filter(r => r.length > 0)

      const maxRetrievals = recipientList.length > 0 ? recipientList.length : 1

      // Upload
      setStatus('uploading')
      setProgress('Uploading encrypted shards to storage nodes...')
      const uploadResult = await uploadTransfer(
        transferName || files[0].name,
        uploadFiles,
        rHash,
        encryptedManifest,
        maxRetrievals,
        setProgress
      )

      setResult({
        code,
        transferName: uploadResult.transfer_name,
        files: uploadResult.files,
        totalBytes: uploadResult.total_bytes,
      })

      // Notify recipients if provided
      if (recipientList.length > 0) {
        setStatus('notifying')
        setProgress(`Sending notifications to ${recipientList.length} recipient(s)...`)
        await notifyRecipients(code, transferName || files[0].name, recipientList, uploadResult.files, uploadResult.total_bytes)
      }

      setStatus('done')
      setProgress('')
    } catch (err: any) {
      setStatus('error')
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
        className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-4 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
      />

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
