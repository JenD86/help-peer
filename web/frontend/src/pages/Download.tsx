import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { deriveKeys, relayHash, decryptSegment, fileHasher } from '../lib/crypto'
import { downloadManifest, downloadSegment, ackDownload, markReceived, type ShardInfo } from '../lib/api'

interface ManifestFile {
  path: string
  size: number
  blake3?: string
  segments: {
    id: string
    original_size: number
    encrypted_size: number
    shards: ShardInfo[]
  }[]
}

interface Manifest {
  version: number
  transfer_name: string
  message?: string
  ack_secret: string
  delete_token: string
  total_bytes: number
  segment_size: number
  erasure_data_shards: number
  erasure_parity_shards: number
  files: ManifestFile[]
}

// Minimal File System Access API typing (Chromium); not in TypeScript's DOM lib.
interface FileWritable {
  write(data: ArrayBuffer): Promise<void>
  close(): Promise<void>
}
interface DirHandle {
  getDirectoryHandle(name: string, opts: { create: boolean }): Promise<DirHandle>
  getFileHandle(name: string, opts: { create: boolean }): Promise<{ createWritable(): Promise<FileWritable> }>
}
const pickDirectory = (window as any).showDirectoryPicker as
  | ((opts: { mode: 'readwrite' }) => Promise<DirHandle>)
  | undefined

// The manifest comes from the sender: split its path and reject anything
// that could escape the chosen folder (same rules as the CLI).
function safePathParts(path: string): string[] {
  const parts = path.split('/')
  if (!path || parts.some(p => p === '' || p === '.' || p === '..' || /[\\:\0]/.test(p))) {
    throw new Error(`Unsafe file path in transfer: ${JSON.stringify(path)}`)
  }
  return parts
}

// Drop control characters (other than newlines and tabs) from sender-supplied
// text before showing it; the CLIs do the same.
const printable = (text: string) => text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '')

const formatBytes = (b: number) => {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`
  return `${(b / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

// A transfer that has been opened (manifest fetched and decrypted) but not
// yet downloaded. Opening doesn't consume it.
interface Opened {
  manifest: Manifest
  kData: ArrayBuffer
  rHash: string
}

function checkManifest(m: Manifest) {
  const isHex64 = (s: unknown) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s)
  if (m.version !== 2 || !isHex64(m.ack_secret) || !isHex64(m.delete_token)) {
    throw new Error('This transfer was made with an incompatible version of Help Peer')
  }
  if (m.message !== undefined && (typeof m.message !== 'string' || m.message.length > 2000)) {
    throw new Error('Invalid transfer message')
  }
  if (m.erasure_data_shards !== 8 || m.erasure_parity_shards !== 4 || !Array.isArray(m.files)) {
    throw new Error('Unsupported transfer format')
  }
  for (const f of m.files) safePathParts(f.path)
}

export default function Download() {
  const [searchParams] = useSearchParams()
  // Prefilled when coming from the inbox
  const [code, setCode] = useState(searchParams.get('code') ?? '')
  const [status, setStatus] = useState<'idle' | 'opening' | 'ready' | 'downloading' | 'done'>('idle')
  const [opened, setOpened] = useState<Opened | null>(null)
  const [progress, setProgress] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [downloadedFiles, setDownloadedFiles] = useState<string[]>([])
  const [ackFailed, setAckFailed] = useState(false)

  // Step 1: fetch and decrypt the manifest to show what's in the transfer.
  const handleOpen = async () => {
    if (!code.trim()) return
    setErrorMsg('')
    setStatus('opening')
    setProgress('Deriving keys from code...')
    try {
      const { kData, kIndex } = await deriveKeys(code)
      const rHash = relayHash(kIndex)

      setProgress('Fetching transfer details...')
      const manifestData = await downloadManifest(rHash)
      let manifest: Manifest
      try {
        manifest = JSON.parse(new TextDecoder().decode(await decryptSegment(kData, manifestData)))
      } catch {
        throw new Error('Could not decrypt the transfer. Check the code.')
      }
      checkManifest(manifest)
      setOpened({ manifest, kData, rHash })
      setStatus('ready')
    } catch (err: any) {
      setStatus('idle')
      setErrorMsg(err.message || 'Could not open the transfer. Check your code.')
    } finally {
      setProgress('')
    }
  }

  // Step 2: download, decrypt and verify every file.
  const handleDownload = async () => {
    if (!opened) return
    const { manifest, kData, rHash } = opened
    setErrorMsg('')

    // Where supported, stream files straight into a folder the user picks,
    // so large transfers never have to fit in memory. The picker must open
    // before any other await, while the click still counts as a user gesture.
    let dir: DirHandle | null = null
    if (pickDirectory) {
      try {
        dir = await pickDirectory({ mode: 'readwrite' })
      } catch (err: any) {
        if (err?.name === 'AbortError') return // user cancelled
      }
    }

    setStatus('downloading')
    try {
      const downloaded: string[] = []
      const total = manifest.total_bytes || 1
      let doneBytes = 0

      for (const file of manifest.files) {
        const parts = safePathParts(file.path)
        const hasher = fileHasher()

        // Open the output: a file in the chosen folder, or an in-memory list of chunks
        let writable: FileWritable | null = null
        const chunks: ArrayBuffer[] = []
        if (dir) {
          let d = dir
          for (const p of parts.slice(0, -1)) d = await d.getDirectoryHandle(p, { create: true })
          writable = await (await d.getFileHandle(parts[parts.length - 1], { create: true })).createWritable()
        }

        for (let si = 0; si < file.segments.length; si++) {
          const seg = file.segments[si]
          setProgress(`Downloading ${file.path} — ${Math.floor((doneBytes / total) * 100)}% overall`)

          const encrypted = await downloadSegment(
            seg.shards,
            seg.encrypted_size,
            manifest.erasure_data_shards,
            manifest.erasure_parity_shards
          )
          const plaintext = await decryptSegment(kData, encrypted)
          hasher.update(plaintext)
          if (writable) await writable.write(plaintext)
          else chunks.push(plaintext)
          doneBytes += plaintext.byteLength
        }

        if (file.blake3 && hasher.hexdigest() !== file.blake3) {
          throw new Error(`${file.path} is corrupt (BLAKE3 mismatch)`)
        }

        if (writable) {
          await writable.close()
        } else {
          // Fallback: hand the assembled file to the browser's download manager
          const url = URL.createObjectURL(new Blob(chunks, { type: 'application/octet-stream' }))
          const a = document.createElement('a')
          a.href = url
          a.download = parts.join('_')
          a.click()
          // Revoking immediately can cancel the download in some browsers
          setTimeout(() => URL.revokeObjectURL(url), 60_000)
        }
        downloaded.push(file.path)
      }

      // Everything verified: confirm, which uses up this recipient's
      // retrieval. If it fails the transfer just expires on its own.
      let acked = true
      try {
        await ackDownload(rHash, manifest.ack_secret)
      } catch {
        acked = false
      }

      // Clear this transfer from the user's inbox, if it was there.
      markReceived(rHash).catch(() => {})

      setAckFailed(!acked)
      setDownloadedFiles(downloaded)
      setStatus('done')
    } catch (err: any) {
      // Stay on the opened transfer so the user can simply try again.
      setStatus('ready')
      setErrorMsg((err.message || 'Download failed.') + ' You can try again.')
    } finally {
      setProgress('')
    }
  }

  const reset = () => {
    setStatus('idle')
    setOpened(null)
    setCode('')
    setDownloadedFiles([])
    setErrorMsg('')
  }

  const busy = status === 'opening' || status === 'downloading'
  const m = opened?.manifest

  return (
    <div className="max-w-md mx-auto px-6 py-16">
      <h1 className="text-3xl font-bold text-gray-900 mb-2">Receive Files</h1>
      <p className="text-gray-600 mb-8">
        Enter the transfer code you received to see what's in it.
        {pickDirectory
          ? " When you download, you'll be asked for a folder to save into."
          : ' Files are assembled in memory, so for very large transfers use the command-line client.'}
      </p>

      {status === 'done' ? (
        <div className="text-center">
          <div className="text-5xl mb-4">✅</div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">Download Complete!</h2>
          <p className="text-gray-600 mb-4">{downloadedFiles.length} file(s) downloaded and verified:</p>
          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            {downloadedFiles.map((f, i) => (
              <div key={i} className="text-sm text-gray-700">{f}</div>
            ))}
          </div>
          {ackFailed && (
            <p className="text-xs text-gray-500 mb-4">
              The relay couldn't be told the download finished, so the transfer stays available until it expires.
            </p>
          )}
          <button onClick={reset} className="text-indigo-600 hover:text-indigo-700 font-medium">
            Receive more files →
          </button>
        </div>
      ) : m ? (
        <div>
          <div className="bg-white border border-gray-200 rounded-lg p-4 mb-4">
            <h2 className="font-semibold text-gray-900 mb-1 break-words">{printable(m.transfer_name) || 'Untitled transfer'}</h2>
            <p className="text-sm text-gray-500 mb-3">
              {m.files.length} file(s) · {formatBytes(m.total_bytes)}
            </p>
            {m.message && (
              <div className="mb-3">
                <p className="text-xs font-medium text-gray-500 mb-1">Message from the sender</p>
                <blockquote className="border-l-4 border-indigo-200 bg-indigo-50/50 px-3 py-2 text-sm text-gray-800 whitespace-pre-wrap break-words">
                  {printable(m.message)}
                </blockquote>
              </div>
            )}
            <ul className="text-sm text-gray-700 max-h-48 overflow-y-auto space-y-1">
              {m.files.map(f => (
                <li key={f.path} className="flex justify-between gap-4">
                  <span className="truncate font-mono text-xs">{f.path}</span>
                  <span className="text-gray-400 shrink-0">{formatBytes(f.size)}</span>
                </li>
              ))}
            </ul>
          </div>
          <button
            onClick={handleDownload}
            disabled={busy}
            className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition mb-3"
          >
            {status === 'downloading' ? 'Downloading...' : 'Download & Decrypt'}
          </button>
          {!busy && (
            <button onClick={reset} className="w-full text-sm text-gray-500 hover:text-gray-700 mb-4">
              Use a different code
            </button>
          )}
        </div>
      ) : (
        <div>
          <input
            type="text"
            placeholder="e.g. orbit-velvet-zoom-candle-harbor-ember"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !busy && handleOpen()}
            className="w-full px-4 py-3 border border-gray-300 rounded-lg mb-4 font-mono text-center text-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
          <button
            onClick={handleOpen}
            disabled={!code.trim() || busy}
            className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 transition mb-4"
          >
            {status === 'opening' ? 'Opening...' : 'Open Transfer'}
          </button>
        </div>
      )}

      {progress && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-700">{progress}</div>
      )}
      {errorMsg && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700 mt-4">{errorMsg}</div>
      )}
    </div>
  )
}
