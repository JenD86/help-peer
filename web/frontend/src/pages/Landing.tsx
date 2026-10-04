import { Link } from 'react-router-dom'

export default function Landing() {
  return (
    <div className="max-w-4xl mx-auto px-6 py-16">
      <div className="text-center">
        <h1 className="text-5xl font-bold text-gray-900 mb-4">
          Send files, <span className="text-indigo-600">end-to-end encrypted</span>
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          Transfer AI model weights, datasets, or any files — encrypted in your browser, stored across decentralized nodes.
        </p>
        <div className="flex gap-4 justify-center">
          <Link
            to="/upload"
            className="bg-indigo-600 text-white px-8 py-3 rounded-lg font-medium hover:bg-indigo-700 transition"
          >
            Send Files
          </Link>
          <Link
            to="/download"
            className="bg-white border border-gray-300 text-gray-700 px-8 py-3 rounded-lg font-medium hover:bg-gray-50 transition"
          >
            Receive Files
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-16">
        <div className="text-center">
          <div className="text-3xl mb-2">🔒</div>
          <h3 className="font-semibold text-gray-900 mb-1">Zero-Knowledge</h3>
          <p className="text-sm text-gray-600">Files are encrypted in your browser. Servers never see plaintext or keys.</p>
        </div>
        <div className="text-center">
          <div className="text-3xl mb-2">🧩</div>
          <h3 className="font-semibold text-gray-900 mb-1">Erasure Coded</h3>
          <p className="text-sm text-gray-600">Files are split into 12 shards across nodes. Any 8 suffice to recover.</p>
        </div>
        <div className="text-center">
          <div className="text-3xl mb-2">📧</div>
          <h3 className="font-semibold text-gray-900 mb-1">Email Notifications</h3>
          <p className="text-sm text-gray-600">Send to multiple recipients with automatic email notifications.</p>
        </div>
      </div>
    </div>
  )
}
