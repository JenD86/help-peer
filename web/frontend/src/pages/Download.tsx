import { useState } from 'react'
import { deriveKeys, relayHash, decryptSegment, base64ToBuf } from '../lib/crypto'
import { downloadManifest, downloadSegment, type ShardInfo } from '../lib/api'

interface ManifestFile {
  path: string
  size: number
  segments: {
    id: string
    encrypted_size: number
    shards: ShardInfo[]
  }[]
}

interface Manifest {
  version: number
  transfer_name: string
  total_bytes: number
  segment_size: number
  erasure_data_shards: number
  erasure_parity_shards: number
  files: ManifestFile[]
}

export default function Download() {
  const [code, setCode] = useState('')
  const [status, setStatus] = useState<'idle' | 'fetching' | 'downloading' | 'decrypting' | 'done' | 'error'>('idle')
  const [progress, setProgress] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [downloadedFiles, setDownloadedFiles] = useState<string[]>([])

  const handleDownload = async () => {
    if (!code.trim()) return
    setStatus('fetching')
    setProgress('Deriving keys from code...')
    setErrorMsg('')

    try {
      const { kData, kIndex } = await deriveKeys(code.trim())
      const rHash = await relayHash(kIndex)

      setProgress('Fetching manifest from relay...')
      const manifestData = await downloadManifest(rHash)

      setProgress('Decrypting manifest...')
      const manifestJson = await decryptSegment(kData, manifestData)
      const manifest: Manifest = JSON.parse(new TextDecoder().decode(manifestJson))

      setProgress(`Downloading ${manifest.files.length} file(s)...`)
      setStatus('downloading')

      const downloaded: string[] = []

      for (let fi = 0; fi < manifest.files.length; fi++) {
        const file = manifest.files[fi]
        const fileChunks: ArrayBuffer[] = []

        for (let si = 0; si < file.segments.length; si++) {
          const seg = file.segments[si]
          setProgress(`Downloading ${file.path} — segment ${si + 1}/${file.segments.length}`)

          const encryptedSegment = await downloadSegment(
            seg.shards,
            manifest.erasure_data_shards,
            manifest.erasure_parity_shards
          )

          setProgress(`Decrypting ${file.path} — segment ${si + 1}/${file.segments.length}`)
          const plaintext = await decryptSegment(kData, encryptedSegment)
          fileChunks.push(plaintext)
        }

        // Combine chunks and trigger download
        const totalSize = fileChunks.reduce((s, c) => s + c.byteLength, 0)
        const combined = new Uint8Array(totalSize)
        let offset = 0
        for (const chunk of fileChunks) {
          combined.set(new Uint8Array(chunk), offset)
          offset += chunk.byteLength
        }

        const blob = new Blob([combined], { type: 'application/octet-stream' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = file.path
        a.click()
        URL.revokeObjectURL(url)
        downloaded.push(file.path)
      }

      setDownloadedFiles(downloaded)
      setStatus('done')
      setProgress('')
    } catch (err: any) {
      setStatus('error')
      setErrorMsg(err.message || 'Download failed. Check your code.')
    }
  }

  return (
    <div className="max-w-md mx-auto px-6 py-16">
      <h1 className="text-3xl font-bold text-gray-900 mb-2">Receive Files</h1>
      <p className="text-gray-600 mb-8">Enter the transfer code you received.</p>

      {status === 'done' ? (
        <div className="text-center">
          <div className="text-5xl mb-4">✅</div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">Download Complete!</h2>
          <p className="text-gray-600 mb-4">{downloadedFiles.length} file(s) downloaded:</p>
          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            {downloadedFiles.map((f, i) => (
              <div key={i} className="text-sm text-gray-700">{f}</div>
            ))}
          </div>
          <button
            onClick={() => {
              setStatus('idle')
              setCode('')
              setDownloadedFiles([])
            }}
            className="text-indigo-600 hover:text-indigo-700 font-medium"
          >
            Receive more files →
          </button>
        </div>
      ) : (
        <div>
          <input
            type="text"
            placeholder="e.g. 38-vortex-xenon"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleDownload()}
            className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-4 font-mono text-center text-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
          <button
            onClick={handleDownload}
            disabled={!code.trim() || status === 'fetching' || status === 'downloading' || status === 'decrypting'}
            className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition mb-4"
          >
            {status === 'fetching' ? 'Fetching...' :
             status === 'downloading' ? 'Downloading...' :
             status === 'decrypting' ? 'Decrypting...' :
             'Download & Decrypt'}
          </button>

          {progress && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-700">
              {progress}
            </div>
          )}

          {status === 'error' && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700 mt-4">
              {errorMsg}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
