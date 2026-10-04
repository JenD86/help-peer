const API_BASE = ''

export interface ShardInfo {
  index: number
  hash: string
  node: string
}

// fetch wrapper that throws with the server's error message on non-2xx.
async function request(path: string, init?: RequestInit): Promise<Response> {
  const resp = await fetch(`${API_BASE}${path}`, init)
  if (!resp.ok) {
    let message = `request failed (${resp.status})`
    try {
      const body = await resp.json()
      if (body.error) message = body.error
    } catch {
      // not JSON; keep the generic message
    }
    throw new Error(message)
  }
  return resp
}

function postJSON(path: string, body: unknown): Promise<Response> {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function requestMagicLink(email: string): Promise<{ status: string; message: string }> {
  return (await postJSON('/api/auth/request', { email })).json()
}

export async function verifyMagicLink(token: string): Promise<{ status: string; email: string }> {
  return (await postJSON('/api/auth/verify', { token })).json()
}

export async function checkAuth(): Promise<{ authenticated: boolean; email?: string }> {
  return (await request('/api/auth/me')).json()
}

export async function logout(): Promise<void> {
  await request('/api/auth/logout', { method: 'POST' })
}

// Upload one encrypted segment; the server erasure-codes it and stores the
// shards, registering deleteTokenHash so only manifest holders can delete them.
export async function uploadSegment(
  encrypted: ArrayBuffer,
  deleteTokenHash: string
): Promise<{ encrypted_size: number; shards: ShardInfo[] }> {
  const resp = await request('/api/upload/segment', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'X-Delete-Token-Hash': deleteTokenHash },
    body: encrypted,
  })
  return resp.json()
}

export async function uploadManifest(params: {
  manifestHash: string
  manifestData: ArrayBuffer
  ackHash: string
  maxRetrievals: number
  transferName: string
  files: number
  totalBytes: number
}): Promise<{ transfer_id?: string }> {
  const resp = await postJSON('/api/upload/manifest', {
    manifest_hash: params.manifestHash,
    manifest_data: arrayBufferToBase64(params.manifestData),
    ack_hash: params.ackHash,
    max_retrievals: params.maxRetrievals,
    transfer_name: params.transferName,
    files: params.files,
    total_bytes: params.totalBytes,
  })
  return resp.json()
}

export async function downloadManifest(manifestHash: string): Promise<ArrayBuffer> {
  const resp = await postJSON('/api/download', { manifest_hash: manifestHash })
  const data = await resp.json()
  return base64ToArrayBuffer(data.manifest_data)
}

// Confirm a completed, verified download. This uses up one of the
// transfer's retrievals; until then the code can be retried.
export async function ackDownload(manifestHash: string, ackSecret: string): Promise<void> {
  await postJSON('/api/download/ack', { manifest_hash: manifestHash, ack_secret: ackSecret })
}

// Fetch one segment, rebuilt from its shards by the server (still encrypted).
export async function downloadSegment(
  shards: ShardInfo[],
  encryptedSize: number,
  dataShards: number,
  parityShards: number
): Promise<ArrayBuffer> {
  const resp = await postJSON('/api/download/segment', {
    shards,
    encrypted_size: encryptedSize,
    data_shards: dataShards,
    parity_shards: parityShards,
  })
  return resp.arrayBuffer()
}

export async function notifyRecipients(
  transferId: string,
  code: string,
  recipients: string[]
): Promise<{ status: string; sent: number; errors?: string[] }> {
  return (await postJSON('/api/notify', { transfer_id: transferId, code, recipients })).json()
}

export async function getHistory(): Promise<{ transfers: any[] }> {
  return (await request('/api/history')).json()
}

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  // Convert in chunks: one String.fromCharCode call per byte is very slow
  // for multi-megabyte manifests, and spreading everything at once overflows the stack.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
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
