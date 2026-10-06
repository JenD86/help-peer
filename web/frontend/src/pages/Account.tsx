import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  getProfile, setProfile, listTokens, createToken, revokeToken, linkEmail, unlinkEmail,
  type Profile, type APIToken,
} from '../lib/api'

export default function Account() {
  const [profile, setProfileState] = useState<Profile | null>(null)
  const [username, setUsername] = useState('')
  const [listed, setListed] = useState(true)
  const [profileMsg, setProfileMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [tokens, setTokens] = useState<APIToken[]>([])
  const [tokenName, setTokenName] = useState('')
  const [newToken, setNewToken] = useState('')
  const [linkEmailAddr, setLinkEmailAddr] = useState('')
  const [emailMsg, setEmailMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getProfile()
      .then(p => {
        setProfileState(p)
        setUsername(p.username)
        setListed(p.username ? p.listed : true)
      })
      .catch(err => setError(err.message || 'Could not load your account'))
    listTokens().then(setTokens).catch(() => {})
  }, [])

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const p = await setProfile(username.trim(), listed)
      setProfileState(p)
      setUsername(p.username)
      setProfileMsg({ ok: true, text: p.username ? 'Saved.' : 'Username removed.' })
    } catch (err: any) {
      setProfileMsg({ ok: false, text: err.message || 'Could not save' })
    }
  }

  const addToken = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const t = await createToken(tokenName.trim() || 'CLI')
      setNewToken(t.token)
      setTokenName('')
      setTokens(await listTokens())
    } catch (err: any) {
      setError(err.message || 'Could not create token')
    }
  }

  const removeToken = async (id: string) => {
    await revokeToken(id).catch(() => {})
    setTokens(prev => prev.filter(t => t.id !== id))
  }

  const handleUnlinkEmail = async () => {
    if (!window.confirm('Remove this email from your account? You will stop getting email notifications.')) return
    try {
      await unlinkEmail()
      setProfileState(prev => (prev ? { ...prev, email: '' } : prev))
      setEmailMsg({ ok: true, text: 'Email removed.' })
    } catch (err: any) {
      setEmailMsg({ ok: false, text: err.message || 'Could not remove the email' })
    }
  }

  const handleLinkEmail = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const resp = await linkEmail(linkEmailAddr.trim())
      setEmailMsg({ ok: true, text: resp.message || 'Check your email to confirm.' })
      setLinkEmailAddr('')
    } catch (err: any) {
      setEmailMsg({ ok: false, text: err.message || 'Could not link email' })
    }
  }

  if (error && !profile) {
    return (
      <div className="max-w-2xl mx-auto px-6 py-16 text-center text-gray-600">
        {error.includes('authentication') ? (
          <p><Link to="/login" className="text-indigo-600">Log in</Link> to manage your account.</p>
        ) : (
          <p className="text-red-600">{error}</p>
        )}
      </div>
    )
  }
  if (!profile) {
    return <div className="max-w-2xl mx-auto px-6 py-16 text-center text-gray-500">Loading...</div>
  }

  return (
    <div className="max-w-2xl mx-auto px-6 py-8 space-y-10">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 mb-1">Account</h1>
        <p className="text-sm text-gray-500">
          Logged in as{' '}
          {profile.username ? <span className="font-medium">@{profile.username}</span> : profile.email || <span className="italic">no email linked</span>}
        </p>
      </div>

      <section>
        <h2 className="text-lg font-semibold text-gray-900 mb-1">Email</h2>
        {profile.email ? (
          <>
            <p className="text-sm text-gray-600">
              Your email is <span className="font-medium">{profile.email}</span>. You'll receive notifications when someone sends you files by username.
            </p>
            <form onSubmit={handleLinkEmail} className="space-y-3 mt-4">
              <label className="block text-sm font-medium text-gray-700">Change email</label>
              <input
                type="email"
                placeholder="new-address@example.com"
                value={linkEmailAddr}
                onChange={e => setLinkEmailAddr(e.target.value)}
                required
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
              <p className="text-xs text-gray-500">
                We'll send a confirmation link to the new address. Your current email stays in place until you confirm it.
              </p>
              <div className="flex items-center gap-4">
                <button type="submit" className="bg-indigo-600 text-white px-6 py-2 rounded-lg font-medium hover:bg-indigo-700">
                  Send confirmation
                </button>
                <button
                  type="button"
                  onClick={handleUnlinkEmail}
                  disabled={!profile.username}
                  title={profile.username ? undefined : 'Set a username first'}
                  className="text-red-600 hover:text-red-700 text-sm disabled:text-gray-400 disabled:cursor-not-allowed"
                >
                  Remove email
                </button>
              </div>
              {!profile.username && (
                <p className="text-xs text-gray-500">Set a username below before removing your email, so you can still log in.</p>
              )}
              {emailMsg && (
                <p className={`text-sm ${emailMsg.ok ? 'text-green-700' : 'text-red-600'}`}>{emailMsg.text}</p>
              )}
            </form>
          </>
        ) : (
          <>
            <p className="text-sm text-gray-500 mb-4">
              Add an email to get notified when someone sends you files by username. We'll send you a verification link.
            </p>
            <form onSubmit={handleLinkEmail} className="space-y-3">
              <input
                type="email"
                placeholder="you@example.com"
                value={linkEmailAddr}
                onChange={e => setLinkEmailAddr(e.target.value)}
                required
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
              <button type="submit" className="bg-indigo-600 text-white px-6 py-2 rounded-lg font-medium hover:bg-indigo-700">
                Link Email
              </button>
              {emailMsg && (
                <p className={`text-sm ${emailMsg.ok ? 'text-green-700' : 'text-red-600'}`}>{emailMsg.text}</p>
              )}
            </form>
          </>
        )}
      </section>

      <section>
        <h2 className="text-lg font-semibold text-gray-900 mb-1">Username</h2>
        <p className="text-sm text-gray-500 mb-4">
          Others can send files to your username. Transfers go to your{' '}
          <Link to="/inbox" className="text-indigo-600">inbox</Link> and you get an email letting you know if you've linked one. Your email
          address is never shown to anyone.
        </p>
        <form onSubmit={saveProfile} className="space-y-3">
          <div className="flex items-center border border-gray-300 rounded-lg focus-within:ring-2 focus-within:ring-indigo-500">
            <span className="pl-4 text-gray-400">@</span>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="your-name"
              className="flex-1 px-2 py-3 rounded-lg outline-none"
            />
          </div>
          <label className="flex items-start gap-2 text-sm text-gray-700">
            <input type="checkbox" checked={listed} onChange={e => setListed(e.target.checked)} className="mt-1" />
            <span>
              List me in the directory, so logged-in users can find me by searching. If unchecked, people need to
              know your exact username.
            </span>
          </label>
          <div className="flex items-center gap-4">
            <button type="submit" className="bg-indigo-600 text-white px-6 py-2 rounded-lg font-medium hover:bg-indigo-700">
              Save
            </button>
            {profileMsg && (
              <span className={`text-sm ${profileMsg.ok ? 'text-green-700' : 'text-red-600'}`}>{profileMsg.text}</span>
            )}
          </div>
        </form>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-gray-900 mb-1">API tokens</h2>
        <p className="text-sm text-gray-500 mb-4">
          Let the command-line client or Python SDK act as you: send to usernames and check your inbox. Treat a
          token like a password.
        </p>

        {newToken && (
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-4 text-sm">
            <p className="font-medium text-amber-900 mb-2">Copy this token now — it won't be shown again.</p>
            <code className="block break-all font-mono text-amber-900 mb-3">{newToken}</code>
            <p className="text-amber-900 mb-1">Then on your computer run:</p>
            <code className="block break-all font-mono text-xs text-amber-800">
              helppeer login --server {window.location.origin} --token {newToken}
            </code>
          </div>
        )}

        <form onSubmit={addToken} className="flex gap-3 mb-4">
          <input
            type="text"
            value={tokenName}
            onChange={e => setTokenName(e.target.value)}
            placeholder="Token name (e.g. laptop)"
            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
          />
          <button type="submit" className="bg-white border border-gray-300 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">
            Create token
          </button>
        </form>

        {tokens.length > 0 && (
          <div className="space-y-2">
            {tokens.map(t => (
              <div key={t.id} className="flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-2 text-sm">
                <div>
                  <span className="font-medium text-gray-800">{t.name}</span>
                  <span className="text-gray-400 ml-2">
                    created {new Date(t.created_at).toLocaleDateString()}
                    {t.last_used && !t.last_used.startsWith('0001') && ` · last used ${new Date(t.last_used).toLocaleDateString()}`}
                  </span>
                </div>
                <button onClick={() => removeToken(t.id)} className="text-red-500 hover:text-red-700">Revoke</button>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
