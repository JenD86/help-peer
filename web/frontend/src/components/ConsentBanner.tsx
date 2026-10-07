import { useEffect, useState } from 'react'

// Analytics consent. index.html defines loadAnalytics() and calls it on page
// load if the visitor accepted before; until then nothing loads from Google.
const KEY = 'analytics-consent'
const GA_ID = 'G-1ZTKJQY0ME'

type Choice = 'granted' | 'denied'

function storedChoice(): Choice | null {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'granted' || v === 'denied' ? v : null
  } catch {
    return null
  }
}

function store(choice: Choice) {
  try {
    localStorage.setItem(KEY, choice)
  } catch {
    // Private mode etc.: the choice lasts until the page is closed.
  }
}

// Stops a tag that was already loaded this visit and removes its cookies.
function disableAnalytics() {
  const w = window as any
  w[`ga-disable-${GA_ID}`] = true
  w.gtag?.('consent', 'update', { analytics_storage: 'denied' })
  for (const c of document.cookie.split(';')) {
    const name = c.split('=')[0].trim()
    if (name === '_ga' || name.startsWith('_ga_')) {
      for (const domain of ['', `; domain=${location.hostname}`, `; domain=.${location.hostname}`]) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/${domain}`
      }
    }
  }
}

export default function ConsentBanner() {
  const [open, setOpen] = useState(() => storedChoice() === null)

  // The footer's "Cookie settings" link reopens the banner.
  useEffect(() => {
    const reopen = () => setOpen(true)
    window.addEventListener('open-consent', reopen)
    return () => window.removeEventListener('open-consent', reopen)
  }, [])

  const choose = (choice: Choice) => {
    store(choice)
    const w = window as any
    if (choice === 'granted') {
      w[`ga-disable-${GA_ID}`] = false
      w.loadAnalytics?.()
      w.gtag?.('consent', 'update', { analytics_storage: 'granted' })
    } else {
      disableAnalytics()
    }
    setOpen(false)
  }

  if (!open) return null
  return (
    <div
      role="dialog"
      aria-label="Cookie consent"
      className="fixed inset-x-0 bottom-0 z-50 p-4 flex justify-center pointer-events-none"
    >
      <div className="pointer-events-auto max-w-2xl w-full bg-white border border-gray-200 rounded-xl shadow-lg p-4 flex flex-col sm:flex-row sm:items-center gap-4">
        <p className="text-sm text-gray-700 flex-1">
          May we use Google Analytics cookies to see how the site is used? It sees which pages you visit and basic
          device details, never your files or transfer codes.
        </p>
        <div className="flex gap-2 shrink-0">
          <button
            onClick={() => choose('denied')}
            className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700"
          >
            Decline
          </button>
          <button
            onClick={() => choose('granted')}
            className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700"
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  )
}
