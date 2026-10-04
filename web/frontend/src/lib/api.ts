const API_BASE = ''

export async function requestMagicLink(email: string): Promise<{ status: string; message: string }> {
  const resp = await fetch(`${API_BASE}/api/auth/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  })
  return resp.json()
}

export async function verifyMagicLink(token: string): Promise<{ status: string; email: string }> {
  const resp = await fetch(`${API_BASE}/api/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  return resp.json()
}

export async function checkAuth(): Promise<{ authenticated: boolean; email?: string }> {
  const resp = await fetch(`${API_BASE}/api/auth/me`)
  return resp.json()
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST' })
}

export interface UploadFile {
  path: string
  size: number
  data: ArrayBuffer
}

export interface UploadResult {
  transfer_name: string
  files: number
  total_bytes: number
}

export async function uploadTransfer(
  transferName: string,
  files: UploadFile[],
  manifestHash: string,
  manifestData: ArrayBuffer,
  maxRetrievals: number,
  onProgress?: (msg: string) => void
): Promise<UploadResult> {
  onProgress?.('Encrypting files...')

  const uploadFiles = files.map(f => ({
    path: f.path,
    size: f.size,
    segments: [{ id: 'seg_000000', encrypted_size: f.data.byteLength, encrypted_data: f.data }],
  }))

  onProgress?.('Uploading to storage nodes...')

  const resp = await fetch(`${API_BASE}/api/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      transfer_name: transferName,
      files: uploadFiles,
      manifest_hash: manifestHash,
      manifest_data: arrayBufferToBase64(manifestData),
      max_retrievals: maxRetrievals,
    }),
  })

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: 'upload failed' }))
    throw new Error(err.error || 'upload failed')
  }

  return resp.json()
}

export async function downloadManifest(manifestHash: string): Promise<ArrayBuffer> {
  const resp = await fetch(`${API_BASE}/api/download`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ manifest_hash: manifestHash }),
  })

  if (!resp.ok) throw new Error('manifest not found')

  const data = await resp.json()
  return base64ToArrayBuffer(data.manifest_data)
}

export interface ShardInfo {
  index: number
  hash: string
  node: string
}

export async function downloadSegment(
  shards: ShardInfo[],
  dataShards: number,
  parityShards: number
): Promise<ArrayBuffer> {
  const resp = await fetch(`${API_BASE}/api/download/segment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ shards, data_shards: dataShards, parity_shards: parityShards }),
  })

  if (!resp.ok) throw new Error('segment download failed')

  const data = await resp.json()
  return base64ToArrayBuffer(data.encrypted_data)
}

export async function notifyRecipients(
  code: string,
  transferName: string,
  recipients: string[],
  files: number,
  totalBytes: number
): Promise<{ status: string; sent: number; errors?: string[] }> {
  const resp = await fetch(`${API_BASE}/api/notify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      transfer_name: transferName,
      recipients,
      files,
      total_bytes: totalBytes,
    }),
  })
  return resp.json()
}

export async function getHistory(): Promise<{ transfers: any[] }> {
  const resp = await fetch(`${API_BASE}/api/history`)
  return resp.json()
}

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}
