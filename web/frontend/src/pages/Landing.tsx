import { Link } from 'react-router-dom'

const REPO = 'https://github.com/JenD86/help-peer'

function Code({ children }: { children: string }) {
  return (
    <pre className="bg-gray-900 text-gray-100 text-sm rounded-lg p-4 overflow-x-auto text-left">
      <code>{children}</code>
    </pre>
  )
}

export default function Landing() {
  return (
    <div className="max-w-4xl mx-auto px-6 py-16">
      <div className="text-center">
        <h1 className="text-5xl font-bold text-gray-900 mb-4">
          Hand off large files, <span className="text-indigo-600">end-to-end encrypted</span>
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          Send large files to a person or an agent with a one-time code — model weights, datasets, tarballs, anything.
          The sender can go offline straight away; the files wait, end-to-end encrypted, for up to 24 hours.
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
          <p className="text-sm text-gray-600">
            Files are encrypted before they leave your machine. Storage servers only ever hold scrambled pieces.
          </p>
        </div>
        <div className="text-center">
          <div className="text-3xl mb-2">🤖</div>
          <h3 className="font-semibold text-gray-900 mb-1">Built for Agents</h3>
          <p className="text-sm text-gray-600">
            A CLI and Python SDK with JSON output, retry-safe downloads and automatic verification.
          </p>
        </div>
        <div className="text-center">
          <div className="text-3xl mb-2">🧩</div>
          <h3 className="font-semibold text-gray-900 mb-1">Resilient</h3>
          <p className="text-sm text-gray-600">
            Each piece of a file is split into 12 shards across storage nodes. Any 8 are enough to rebuild it.
          </p>
        </div>
      </div>

      <section className="mt-20">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">For agents and scripts</h2>
        <p className="text-gray-600 mb-4">
          Every command is non-interactive and supports <code>--json</code>: one JSON object on stdout, exit code 0 on
          success. Interrupted downloads resume when you run <code>receive</code> again with the same code.
        </p>
        <Code>{`pip install helppeer
helppeer login --server ${typeof window !== 'undefined' ? window.location.origin : 'https://this-site'} --token <API token>

helppeer --json send ./model-dir --name "my-finetune"     # → {"status": "ok", "code": "...", ...}
helppeer --json receive <code> --output ./model-dir      # → files with verified BLAKE3 hashes
helppeer --json send ./dataset-dir --to alice            # deliver to a username's inbox`}</Code>
        <p className="text-sm text-gray-500 mt-3">
          Create an API token on your <Link to="/account" className="text-indigo-600">Account</Link> page. Agents can
          read a compact guide at <a href="/llms.txt" className="text-indigo-600">/llms.txt</a>; the full output
          reference is in the <a href={`${REPO}#for-ai-agents`} className="text-indigo-600">README</a>.
        </p>
      </section>

      <section className="mt-16">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Storage nodes</h2>
        <p className="text-gray-600 mb-3">
          While a transfer waits for its recipient, its encrypted shards live on <strong>storage nodes</strong>: small
          servers run by this site and by volunteers. A node only ever sees ciphertext named by its hash, never file
          names, contents or codes, and it deletes everything after 24 hours. The more independent nodes there are, the
          more failures every transfer can survive.
        </p>
        <h3 className="font-semibold text-gray-900 mb-2">Contribute a node</h3>
        <p className="text-gray-600 mb-3">
          Got a server with spare disk and bandwidth? Run a node (here with 100 GB of space), put it behind HTTPS, and
          point it at this site — it registers itself automatically.
        </p>
        <Code>{`git clone ${REPO} && cd help-peer
docker run -d --restart unless-stopped -p 7001:7001 -v helppeer-shards:/data \\
  -e STORAGE_CAPACITY=107374182400 \\
  -e STORAGE_PUBLIC_URL=https://your-node.example.com \\
  -e HELPEER_REGISTER_URL=${window.location.origin} \\
  $(docker build -q ./storage-node)
curl http://localhost:7001/health`}</Code>
        <p className="text-sm text-gray-500 mt-3">
          Details on costs, S3-backed nodes and what operators can see are in the{' '}
          <a href={`${REPO}#storage-nodes`} className="text-indigo-600">README</a>.
        </p>
      </section>
    </div>
  )
}
