import { readFile } from 'node:fs/promises'
import { dirname, extname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { FastifyInstance, FastifyReply } from 'fastify'
import fastifyStatic from '@fastify/static'
import { normalizeVirtualHost } from '@maildev/core'

const __dirname = dirname(fileURLToPath(import.meta.url))

export interface RegisterUIOptions {
  basePath?: string
  virtualHostPath?: boolean
  /** Directory containing the built UI. Defaults to the packaged `dist/`. */
  distPath?: string
}

/** Strip trailing slashes: '/mail/' -> '/mail', '/' -> ''. */
function stripTrailingSlash(path: string): string {
  return path.replace(/\/+$/, '')
}

/**
 * Inject a `<base href="{basePath}/">` tag into index.html.
 *
 * The Vite build emits relative asset URLs (`base: './'`), and the client
 * derives its REST/Socket.io prefixes from `document.baseURI`. Both rely on
 * this tag so MailDev can be served at the root or under a reverse-proxy
 * sub-path without a rebuild.
 */
export function injectBaseTag(html: string, basePath: string): string {
  const href = `${stripTrailingSlash(basePath)}/`
  return html.replace(
    /<head(\s[^>]*)?>/i,
    (match) => `${match}\n    <base href="${escapeHtmlAttribute(href)}" />`
  )
}

function escapeHtmlAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

export async function registerUI(
  fastify: FastifyInstance,
  options: RegisterUIOptions = {}
): Promise<void> {
  const basePath = stripTrailingSlash(options.basePath ?? '')
  const distPath = options.distPath ?? resolve(__dirname, '..', 'dist')

  // Pre-render index.html with the <base> tag for the configured base path.
  const rawIndex = await readFile(resolve(distPath, 'index.html'), 'utf8')

  if (options.virtualHostPath) {
    await fastify.register(fastifyStatic, { root: distPath, serve: false })
    for (const path of new Set([basePath || '/', `${basePath}/`])) {
      fastify.get(path, async (_request, reply) =>
        reply.status(404).send({ error: 'Missing virtual host' })
      )
    }
    fastify.get<{ Params: { virtualHost: string } }>(
      `${basePath}/:virtualHost`,
      async (request, reply) => {
        try {
          if (!request.params.virtualHost.trim()) throw new Error('Missing virtual host')
          const host = normalizeVirtualHost(request.params.virtualHost)
          const search = new URL(request.url, 'http://maildev.local').search
          return reply.redirect(`${basePath}/${encodeURIComponent(host)}/${search}`)
        } catch {
          return reply.status(400).send({ error: 'Invalid virtual host' })
        }
      }
    )
    fastify.get<{ Params: { virtualHost: string; '*': string } }>(
      `${basePath}/:virtualHost/*`,
      async (request, reply) => {
        let host: string
        try {
          if (!request.params.virtualHost.trim()) throw new Error('Missing virtual host')
          host = normalizeVirtualHost(request.params.virtualHost)
        } catch {
          return reply.status(400).send({ error: 'Invalid virtual host' })
        }
        const file = request.params['*']
        const reserved = /^(api|mcp|socket\.io)(\/|$)/.test(file)
        const isPage =
          !file ||
          file === 'index.html' ||
          (!reserved && !extname(file) && request.headers.accept?.includes('text/html'))
        if (isPage) {
          const html = injectBaseTag(rawIndex, `${basePath}/${encodeURIComponent(host)}`).replace(
            /<head(\s[^>]*)?>/i,
            (match) =>
              `${match}\n    <meta name="maildev-virtual-host" content="${escapeHtmlAttribute(host)}" />` +
              `\n    <meta name="maildev-socket-path" content="${escapeHtmlAttribute(`${basePath}/socket.io`)}" />`
          )
          return reply.type('text/html').send(html)
        }
        if (reserved) return reply.status(404).send({ error: 'Not found' })
        return reply.sendFile(file)
      }
    )
    fastify.setNotFoundHandler(async (_request, reply) =>
      reply.status(404).send({ error: 'Not found' })
    )
    return
  }

  const indexHtml = injectBaseTag(rawIndex, basePath)
  const sendIndex = (reply: FastifyReply) => reply.type('text/html').send(indexHtml)

  // Serve hashed assets under the base path prefix. `index: false` leaves
  // index.html to the handlers below so the injected <base> tag is always used.
  await fastify.register(fastifyStatic, {
    root: distPath,
    prefix: basePath || '/',
    wildcard: false,
    index: false,
  })

  // SPA fallback - serves index.html for unmatched GET requests (incl. the
  // base path root itself, which `index: false` no longer auto-serves).
  fastify.setNotFoundHandler(async (request, reply) => {
    const acceptHeader = request.headers.accept || ''
    if (request.method === 'GET' && acceptHeader.includes('text/html')) {
      return sendIndex(reply)
    }
    return reply.status(404).send({ error: 'Not found' })
  })
}
