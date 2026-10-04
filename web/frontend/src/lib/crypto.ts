/**
 * Browser-side crypto for Help Peer.
 * Implements the same scheme as the Rust CLI and Python SDK (protocol/SPEC.md),
 * so codes work across all clients: HKDF-SHA256 and AES-256-GCM via WebCrypto,
 * BLAKE3 via @noble/hashes.
 */
import { blake3 } from '@noble/hashes/blake3'
import wordlistText from './wordlist.txt?raw'

const enc = new TextEncoder()

// Canonicalize a typed-in code so "Apple Banana", " apple-banana " and
// "APPLE-BANANA" all derive the same keys.
export function normalizeCode(code: string): string {
  return code.split(/[-\s]+/).filter(w => w.length > 0).map(w => w.toLowerCase()).join('-')
}

// K_data / K_index = HKDF-SHA256(ikm = code, no salt, info = label). There is
// no PAKE: sender and receiver are never online together, so the code itself
// is the shared secret.
export async function deriveKeys(code: string): Promise<{ kData: ArrayBuffer; kIndex: ArrayBuffer }> {
  const ikm = await crypto.subtle.importKey('raw', enc.encode(normalizeCode(code)), 'HKDF', false, ['deriveBits'])
  const derive = (info: string) =>
    crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
      ikm,
      256
    )
  return { kData: await derive('help-peer-data-key'), kIndex: await derive('help-peer-index-key') }
}

// Relay hash = BLAKE3(K_index) hex-encoded
export function relayHash(kIndex: ArrayBuffer): string {
  return toHex(blake3(new Uint8Array(kIndex)))
}

// AES-256-GCM encrypt. Returns nonce || ciphertext || tag.
export async function encryptSegment(kData: ArrayBuffer, plaintext: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', kData, 'AES-GCM', false, ['encrypt'])
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext)
  const result = new Uint8Array(nonce.length + ciphertext.byteLength)
  result.set(nonce, 0)
  result.set(new Uint8Array(ciphertext), nonce.length)
  return result.buffer
}

// AES-256-GCM decrypt of nonce || ciphertext || tag.
export async function decryptSegment(kData: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey('raw', kData, 'AES-GCM', false, ['decrypt'])
  const bytes = new Uint8Array(data)
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12))
}

// Incremental BLAKE3 for whole-file hashes.
export function fileHasher() {
  const h = blake3.create({})
  return {
    update: (chunk: ArrayBuffer) => h.update(new Uint8Array(chunk)),
    hexdigest: () => toHex(h.digest()),
  }
}

// Number of words in a transfer code. Each word from the 7776-word EFF list
// adds ~12.9 bits, so 6 words gives ~77 bits. The code is the only secret,
// so it must resist offline brute force and enumeration of the relay.
const CODE_WORDS = 6
const WORDS = wordlistText.split('\n').filter(w => w.length > 0)

// Uniform random index in [0, n) from the CSPRNG, using rejection sampling to avoid modulo bias
function randomIndex(n: number): number {
  const limit = Math.floor(0x100000000 / n) * n
  const buf = new Uint32Array(1)
  do {
    crypto.getRandomValues(buf)
  } while (buf[0] >= limit)
  return buf[0] % n
}

// Generate a transfer code: word-word-word-word-word-word
export function generateCode(): string {
  return Array.from({ length: CODE_WORDS }, () => WORDS[randomIndex(WORDS.length)]).join('-')
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}
