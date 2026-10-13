import { createHash } from 'node:crypto'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

// Adds integrity="sha384-..." to the script and stylesheet tags in index.html,
// so that file alone pins every JS and CSS file the page loads. That only holds
// while the build is one JS file and one CSS file, so more than that is an error.
function integrity(): Plugin {
  return {
    name: 'integrity',
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        if (!ctx.bundle) return html
        const files = Object.values(ctx.bundle)
        const scripts = files.filter((f) => f.fileName.endsWith('.js'))
        const styles = files.filter((f) => f.fileName.endsWith('.css'))
        if (scripts.length !== 1 || styles.length > 1) {
          throw new Error('integrity: expected one JS file and at most one CSS file')
        }

        return html.replace(/<(script|link)\b[^>]*>/g, (tag) => {
          const url = tag.match(/\b(?:src|href)="\/(assets\/[^"]+)"/)
          const file = url && ctx.bundle?.[url[1]]
          if (!file) return tag
          const data = file.type === 'chunk' ? file.code : file.source
          const hash = createHash('sha384').update(data).digest('base64')
          return tag.replace(/\s*\/?>$/, (end) => ` integrity="sha384-${hash}"${end}`)
        })
      },
    },
  }
}

export default defineConfig({
  plugins: [react(), integrity()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
    },
  },
  build: {
    outDir: '../backend/static',
    emptyOutDir: true,
  },
})
