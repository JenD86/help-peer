/**
 * Browser-side crypto for Help Peer.
 * Uses WebCrypto API for AES-256-GCM and HKDF.
 * Uses SHA-256 as content hash (BLAKE3 not available in WebCrypto; SHA-256 is fine for shard addressing).
 */

const enc = new TextEncoder()
const dec = new TextDecoder()

// Code-based key derivation: simulates SPAKE2 -> HKDF
// For the web version, we derive keys from the transfer code using PBKDF2 + HKDF
export async function deriveKeys(code: string): Promise<{ kData: ArrayBuffer; kIndex: ArrayBuffer }> {
  // Derive a shared secret from the code using PBKDF2
  const codeBytes = enc.encode(code)
  const salt = enc.encode('help-peer-salt-v1')

  const baseKey = await crypto.subtle.importKey('raw', codeBytes, 'PBKDF2', false, ['deriveBits'])
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    64 // 512 bits = 2 x 256-bit keys
  )

  // Split into two halves
  const secretBytes = new Uint8Array(sharedSecret)
  const half = secretBytes.length / 2

  // K_data = HKDF(first half, "help-peer-data-key")
  const kDataBase = await crypto.subtle.importKey('raw', secretBytes.slice(0, half), 'HKDF', false, ['deriveBits'])
  const kData = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('help-peer-data-key') },
    kDataBase,
    256
  )

  // K_index = HKDF(second half, "help-peer-index-key")
  const kIndexBase = await crypto.subtle.importKey('raw', secretBytes.slice(half), 'HKDF', false, ['deriveBits'])
  const kIndex = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('help-peer-index-key') },
    kIndexBase,
    256
  )

  return { kData, kIndex }
}

// Relay hash = SHA-256(K_index) hex-encoded
export async function relayHash(kIndex: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', kIndex)
  return toHex(new Uint8Array(hash))
}

// AES-256-GCM encrypt
export async function encryptSegment(kData: ArrayBuffer, plaintext: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', kData, 'AES-GCM', false, ['encrypt'])
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    plaintext
  )
  // Prepend nonce: nonce || ciphertext
  const result = new Uint8Array(nonce.length + ciphertext.byteLength)
  result.set(nonce, 0)
  result.set(new Uint8Array(ciphertext), nonce.length)
  return result.buffer
}

// AES-256-GCM decrypt
export async function decryptSegment(kData: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', kData, 'AES-GCM', false, ['decrypt'])
  const bytes = new Uint8Array(data)
  const nonce = bytes.slice(0, 12)
  const ciphertext = bytes.slice(12)
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    ciphertext
  )
}

// SHA-256 content hash for shard addressing
export async function contentHash(data: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', data)
  return toHex(new Uint8Array(hash))
}

// Generate a transfer code: {number}-{word}-{word}
const WORDS = [
  'orbit', 'velvet', 'xenon', 'vortex', 'quartz', 'photon', 'nebula', 'copper',
  'silver', 'cobalt', 'zephyr', 'aurora', 'crystal', 'onyx', 'amber', 'willow',
  'maple', 'cedar', 'falcon', 'heron', 'otter', 'bison', 'lynx', 'moose',
  'raven', 'swift', 'tiger', 'wolf', 'bear', 'dove', 'hawk', 'ibis',
  'koala', 'lemur', 'panda', 'seal', 'vole', 'yak', 'zebra', 'dolphin',
]

export function generateCode(): string {
  const n = Math.floor(Math.random() * 99) + 1
  const w1 = WORDS[Math.floor(Math.random() * WORDS.length)]
  const w2 = WORDS[Math.floor(Math.random() * WORDS.length)]
  return `${n}-${w1}-${w2}`
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ArrayBuffer <-> Base64 for JSON transport
export function bufToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function base64ToBuf(b64: string): ArrayBuffer {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}
