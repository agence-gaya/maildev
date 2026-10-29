// @vitest-environment node
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Fastify, { type FastifyInstance } from 'fastify'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { registerUI } from './index'

const INDEX_HTML =
  '<!doctype html>\n<html>\n  <head>\n    <link rel="icon" href="./maildev-icon.svg" />\n' +
  '    <title>MailDev</title>\n  </head>\n  <body>\n    <script type="module" src="./assets/app.js"></script>\n  </body>\n</html>'

let distPath: string

beforeAll(async () => {
  // Build a fake UI dist so the test doesn't depend on a real Vite build.
  distPath = await mkdtemp(join(tmpdir(), 'maildev-ui-'))
  await mkdir(join(distPath, 'assets'), { recursive: true })
  await writeFile(join(distPath, 'index.html'), INDEX_HTML)
  await writeFile(join(distPath, 'assets', 'app.js'), 'console.log("app")')
  await writeFile(join(distPath, 'maildev-icon.svg'), '<svg/>')
})

afterAll(async () => {
  await rm(distPath, { recursive: true, force: true })
})

async function buildServer(basePath: string): Promise<FastifyInstance> {
  const app = Fastify()
  await registerUI(app, { basePath, distPath })
  await app.ready()
  return app
}

describe('registerUI', () => {
  describe.each([
    { basePath: '', root: '/', label: 'root' },
    { basePath: '/mail', root: '/mail/', label: 'sub-path' },
  ])('served under $label (basePath=$basePath)', ({ basePath, root }) => {
    it('serves index.html with a <base> tag for the base path', async () => {
      const app = await buildServer(basePath)
      const res = await app.inject({
        method: 'GET',
        url: root,
        headers: { accept: 'text/html' },
      })
      expect(res.statusCode).toBe(200)
      expect(res.headers['content-type']).toContain('text/html')
      expect(res.body).toContain(`<base href="${basePath}/" />`)
      await app.close()
    })

    it('serves hashed assets under the base path prefix', async () => {
      const app = await buildServer(basePath)
      const res = await app.inject({ method: 'GET', url: `${basePath}/assets/app.js` })
      expect(res.statusCode).toBe(200)
      expect(res.body).toContain('console.log')
      await app.close()
    })

    it('falls back to index.html for unknown HTML routes (SPA)', async () => {
      const app = await buildServer(basePath)
      const res = await app.inject({
        method: 'GET',
        url: `${basePath}/does-not-exist`,
        headers: { accept: 'text/html' },
      })
      expect(res.statusCode).toBe(200)
      expect(res.body).toContain(`<base href="${basePath}/" />`)
      await app.close()
    })

    it('returns JSON 404 for unknown non-HTML routes', async () => {
      const app = await buildServer(basePath)
      const res = await app.inject({
        method: 'GET',
        url: `${basePath}/api/missing`,
        headers: { accept: 'application/json' },
      })
      expect(res.statusCode).toBe(404)
      expect(res.json()).toEqual({ error: 'Not found' })
      await app.close()
    })
  })

  it('normalizes a base path with a trailing slash', async () => {
    const app = await buildServer('/mail/')
    const res = await app.inject({ method: 'GET', url: '/mail/', headers: { accept: 'text/html' } })
    expect(res.body).toContain('<base href="/mail/" />')
    expect(res.body).not.toContain('<base href="/mail//')
    await app.close()
  })

  it.each(['', '/maildev', '/apps/mail'])(
    'serves path-based inboxes and assets below %s',
    async (basePath) => {
      const app = Fastify()
      await registerUI(app, { basePath, distPath, virtualHostPath: true })
      await app.ready()
      try {
        for (const host of ['alpha.test', 'beta.test']) {
          const page = await app.inject({
            url: `${basePath}/${host}/`,
            headers: { accept: 'text/html' },
          })
          expect(page.statusCode).toBe(200)
          expect(page.body).toContain(`<base href="${basePath}/${host}/" />`)
          expect(page.body).toContain(`<meta name="maildev-virtual-host" content="${host}" />`)
          expect(page.body).toContain(
            `<meta name="maildev-socket-path" content="${basePath}/socket.io" />`
          )
          const asset = await app.inject(`${basePath}/${host}/assets/app.js`)
          expect(asset.statusCode).toBe(200)
          expect(asset.body).toContain('console.log')
          const index = await app.inject(`${basePath}/${host}/index.html`)
          expect(index.body).toContain(`<base href="${basePath}/${host}/" />`)
          const spa = await app.inject({
            url: `${basePath}/${host}/inbox`,
            headers: { accept: 'text/html' },
          })
          expect(spa.body).toContain(`<base href="${basePath}/${host}/" />`)
          const redirect = await app.inject(`${basePath}/${host}?email=mail-123`)
          expect(redirect.statusCode).toBe(302)
          expect(redirect.headers.location).toBe(`${basePath}/${host}/?email=mail-123`)
        }
        const missing = await app.inject({ url: `${basePath}/`, headers: { accept: 'text/html' } })
        expect(missing.statusCode).toBe(404)
        const invalid = await app.inject({
          url: `${basePath}/bad%2Fhost/`,
          headers: { accept: 'text/html' },
        })
        expect(invalid.statusCode).toBe(400)
      } finally {
        await app.close()
      }
    }
  )
})
