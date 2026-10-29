import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAPIServer, type APIServer } from '../server.js'
import { MemoryStorage, VirtualHostStorage, type Email } from '@maildev/core'
import { SMTPServer } from '@maildev/smtp'
import type { Server as SocketServer } from 'socket.io'

function makeEmail(id: string, host: string): Email {
  return {
    id,
    time: new Date(),
    read: false,
    subject: `Mail for ${host}`,
    source: `/tmp/${id}.eml`,
    size: 1,
    sizeHuman: '1 B',
    from: [{ address: 'sender@example.com' }],
    to: [{ address: 'recipient@example.com' }],
    headers: {},
    attachments: [],
    envelope: {
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@example.com' }],
      host,
    },
  }
}

describe('virtual host API isolation', () => {
  let server: APIServer | undefined
  let storage: VirtualHostStorage

  afterEach(async () => {
    await server?.stop()
    await storage?.close()
    server = undefined
  })

  it('lists and deletes only emails belonging to the request Host', async () => {
    storage = new VirtualHostStorage()
    await storage.initialize()
    const alpha = storage.forHost('alpha.test')
    const beta = storage.forHost('beta.test')
    await alpha.save(makeEmail('alpha-mail', 'alpha.test'))
    await beta.save(makeEmail('beta-mail', 'beta.test'))

    server = createAPIServer({
      storage,
      port: 0,
      virtualHost: true,
    })
    await server.start()

    const alphaList = await server.server.inject({
      method: 'GET',
      url: '/api/email',
      headers: { host: 'alpha.test' },
    })
    expect(alphaList.statusCode).toBe(200)
    expect(alphaList.json().map((email: Email) => email.id)).toEqual(['alpha-mail'])

    const crossHostRead = await server.server.inject({
      method: 'GET',
      url: '/api/email/beta-mail',
      headers: { host: 'alpha.test' },
    })
    expect(crossHostRead.statusCode).toBe(404)

    const deleteAlpha = await server.server.inject({
      method: 'DELETE',
      url: '/api/email/all',
      headers: { host: 'alpha.test' },
    })
    expect(deleteAlpha.statusCode).toBe(200)
    expect(await beta.count()).toBe(1)
  })

  it('selects and isolates inboxes from the path instead of HTTP Host', async () => {
    storage = new VirtualHostStorage()
    await storage.initialize()
    await storage.forHost('alpha.test').save(makeEmail('alpha-mail', 'alpha.test'))
    await storage.forHost('beta.test').save(makeEmail('beta-mail', 'beta.test'))
    server = createAPIServer({
      storage,
      port: 0,
      basePath: '/maildev',
      virtualHostPath: true,
    })
    await server.start()

    const selected = await server.server.inject({
      url: '/maildev/alpha.test/api/email',
      headers: { host: 'beta.test' },
    })
    expect(selected.statusCode).toBe(200)
    expect(selected.json().map((email: Email) => email.id)).toEqual(['alpha-mail'])
    const summary = await server.server.inject('/maildev/alpha.test/api/email/summary')
    expect(summary.json().items.map((email: Email) => email.id)).toEqual(['alpha-mail'])
    const crossed = await server.server.inject('/maildev/beta.test/api/email/alpha-mail')
    expect(crossed.statusCode).toBe(404)
    const missing = await server.server.inject('/maildev/api/email')
    expect(missing.statusCode).toBe(404)
    const invalid = await server.server.inject('/maildev/bad%2Fhost/api/email')
    expect(invalid.statusCode).toBe(400)
    const health = await server.server.inject('/maildev/api/healthz')
    expect(health.statusCode).toBe(200)
    const removed = await server.server.inject({
      method: 'DELETE',
      url: '/maildev/alpha.test/api/email/all',
    })
    expect(removed.statusCode).toBe(200)
    expect(await storage.forHost('beta.test').count()).toBe(1)
  })

  it.each([false, true])(
    'binds MCP sessions to their selected host (path=%s)',
    async (virtualHostPath) => {
      storage = new VirtualHostStorage()
      await storage.initialize()
      server = createAPIServer({
        storage,
        port: 0,
        virtualHost: !virtualHostPath,
        virtualHostPath,
        mcp: { enabled: true },
      })
      await server.start()

      const init = await server.server.inject({
        method: 'POST',
        url: virtualHostPath ? '/alpha.test/mcp' : '/mcp',
        headers: {
          host: 'alpha.test',
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        payload: {
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'test', version: '1.0' },
          },
        },
      })
      expect(init.statusCode).toBe(200)

      const crossHost = await server.server.inject({
        method: 'POST',
        url: virtualHostPath ? '/beta.test/mcp' : '/mcp',
        headers: {
          host: 'beta.test',
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'mcp-session-id': init.headers['mcp-session-id'] as string,
        },
        payload: { jsonrpc: '2.0', id: 2, method: 'ping' },
      })
      expect(crossHost.statusCode).toBe(400)
    }
  )

  it('targets realtime notifications only at the originating host room', async () => {
    const mailDir = await mkdtemp(join(tmpdir(), 'maildev-api-events-'))
    storage = new VirtualHostStorage()
    await storage.initialize()
    const source = new SMTPServer({ storage, mailDir, virtualHost: true, logger: false })

    try {
      server = createAPIServer({ storage, smtp: source, virtualHost: true, port: 0 })
      await server.start()
      const io = (server as unknown as { io: SocketServer }).io
      const targeted = vi.spyOn(io, 'to')
      const broadcast = vi.spyOn(io, 'emit')

      source.emit('new', makeEmail('alpha-mail', 'alpha.test'))
      source.emit('delete', { id: 'alpha-mail', host: 'alpha.test' })
      source.emit('relay', { id: 'alpha-mail', host: 'alpha.test' })

      expect(targeted).toHaveBeenNthCalledWith(1, 'virtual-host:alpha.test')
      expect(targeted).toHaveBeenNthCalledWith(2, 'virtual-host:alpha.test')
      expect(targeted).toHaveBeenNthCalledWith(3, 'virtual-host:alpha.test')
      expect(targeted).toHaveBeenCalledTimes(3)
      expect(broadcast).not.toHaveBeenCalled()
    } finally {
      await source.stop()
      await rm(mailDir, { recursive: true, force: true })
    }
  })

  it('joins only the path-selected realtime room and rejects invalid selectors', async () => {
    const mailDir = await mkdtemp(join(tmpdir(), 'maildev-api-path-sockets-'))
    storage = new VirtualHostStorage()
    await storage.initialize()
    const source = new SMTPServer({ storage, mailDir, virtualHost: true, logger: false })
    const connections: string[] = []
    try {
      server = createAPIServer({
        storage,
        smtp: source,
        port: 0,
        basePath: '/maildev',
        virtualHostPath: true,
      })
      await server.start()
      const connect = async (virtualHost?: string) => {
        const url = `http://127.0.0.1:${server!.getPort()}/maildev/socket.io/?EIO=4&transport=polling`
        const opening = await (await fetch(url, { signal: AbortSignal.timeout(2000) })).text()
        expect(opening).toMatch(/^0/)
        const { sid } = JSON.parse(opening.slice(1)) as { sid: string }
        const endpoint = `${url}&sid=${sid}`
        connections.push(endpoint)
        // Complete the Socket.IO handshake after the Engine.IO opening packet.
        await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: `40${JSON.stringify({ virtualHost })}`,
          signal: AbortSignal.timeout(2000),
        })
        const packet = await (await fetch(endpoint, { signal: AbortSignal.timeout(2000) })).text()
        return { endpoint, packet }
      }
      const alpha = await connect('alpha.test')
      const otherAlpha = await connect('alpha.test')
      const beta = await connect('beta.test')
      expect(alpha.packet).toMatch(/^40/)
      expect(otherAlpha.packet).toMatch(/^40/)
      expect(beta.packet).toMatch(/^40/)
      expect((await connect('../outside')).packet).toMatch(/^44/)
      expect((await connect()).packet).toMatch(/^44/)

      const io = (server as unknown as { io: SocketServer }).io
      expect(io.of('/').adapter.rooms.get('virtual-host:alpha.test')?.size).toBe(2)
      expect(io.of('/').adapter.rooms.get('virtual-host:beta.test')?.size).toBe(1)
      expect(io.of('/').adapter.rooms.has('virtual-host:127.0.0.1')).toBe(false)
      const poll = async (endpoint: string) =>
        (await fetch(endpoint, { signal: AbortSignal.timeout(2000) })).text()
      const relayed = poll(alpha.endpoint)
      const otherRelayed = poll(otherAlpha.endpoint)
      source.emit('relay', { id: 'alpha-mail', host: 'alpha.test' })
      for (const notification of await Promise.all([relayed, otherRelayed])) {
        expect(notification).toBe('42["relayMail",{"id":"alpha-mail"}]')
      }
    } finally {
      await Promise.all(
        connections.map((endpoint) =>
          fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: '1',
            signal: AbortSignal.timeout(2000),
          })
        )
      )
      await source.stop()
      await rm(mailDir, { recursive: true, force: true })
    }
  })

  it.each([false, true])(
    'relays and serves files from the selected inbox (path=%s)',
    async (virtualHostPath) => {
      const mailDir = await mkdtemp(join(tmpdir(), 'maildev-api-relay-source-'))
      const destinationDir = await mkdtemp(join(tmpdir(), 'maildev-api-relay-destination-'))
      const destinationStorage = new MemoryStorage()
      let source: SMTPServer | undefined
      let destination: SMTPServer | undefined

      try {
        storage = new VirtualHostStorage({ mailDirectory: mailDir })
        await storage.initialize()
        const alpha = storage.forHost('alpha.test')
        await alpha.initialize()
        const email = makeEmail('alpha-mail', 'alpha.test')
        email.html = '<img src="cid:attachment">'
        email.attachments = [
          {
            filename: 'attachment.txt',
            generatedFileName: 'attachment.txt',
            contentType: 'text/plain',
            contentDisposition: 'attachment',
            contentId: 'attachment',
          },
        ]
        await alpha.save(email)
        await writeFile(
          join(mailDir, 'alpha.test', 'alpha-mail.eml'),
          [
            'From: sender@example.com',
            'To: recipient@example.com',
            'Subject: Relay test',
            '',
            'Message body',
            '',
          ].join('\r\n')
        )
        await writeFile(
          join(mailDir, 'alpha.test', 'alpha-mail', 'attachment.txt'),
          'attachment body'
        )

        destination = new SMTPServer({
          storage: destinationStorage,
          mailDir: destinationDir,
          port: 0,
          host: '127.0.0.1',
          logger: false,
        })
        await destination.start()
        source = new SMTPServer({ storage, mailDir, virtualHost: true, logger: false })
        source.setupRelay({ host: '127.0.0.1', port: destination.getPort() })

        server = createAPIServer({
          storage,
          smtp: source,
          virtualHost: !virtualHostPath,
          virtualHostPath,
          basePath: virtualHostPath ? '/maildev' : '',
          port: 0,
        })
        await server.start()
        const alphaPath = virtualHostPath ? '/maildev/alpha.test' : ''
        const betaPath = virtualHostPath ? '/maildev/beta.test' : ''
        const selectedHost = virtualHostPath ? 'proxy.test' : 'alpha.test'
        const otherHost = virtualHostPath ? 'proxy.test' : 'beta.test'

        const html = await server.server.inject({
          url: `${alphaPath}/api/email/alpha-mail/html`,
          headers: { host: selectedHost },
        })
        expect(html.statusCode).toBe(200)
        expect(html.body).toContain(`${alphaPath}/api/email/alpha-mail/attachment/attachment.txt`)

        const attachment = await server.server.inject({
          method: 'GET',
          url: `${alphaPath}/api/email/alpha-mail/attachment/attachment.txt`,
          headers: { host: selectedHost },
        })
        expect(attachment.statusCode).toBe(200)
        expect(attachment.body).toBe('attachment body')

        for (const path of ['source', 'download', 'html', 'attachment/attachment.txt']) {
          const crossHostDownload = await server.server.inject({
            method: 'GET',
            url: `${betaPath}/api/email/alpha-mail/${path}`,
            headers: { host: otherHost },
          })
          expect(crossHostDownload.statusCode).toBe(404)
        }

        const crossHostRelay = await server.server.inject({
          method: 'POST',
          url: `${betaPath}/api/email/alpha-mail/relay/override@example.net`,
          headers: { host: otherHost },
        })
        expect(crossHostRelay.statusCode).toBe(500)
        expect(await destinationStorage.count()).toBe(0)

        const response = await server.server.inject({
          method: 'POST',
          url: `${alphaPath}/api/email/alpha-mail/relay/override@example.net`,
          headers: { host: selectedHost },
        })

        expect(response.statusCode).toBe(200)
        const original = await alpha.getById('alpha-mail')
        expect(original?.to).toEqual([{ address: 'recipient@example.com' }])
        expect(original?.envelope.to).toEqual([{ address: 'recipient@example.com' }])
        expect(original?.relayedTo).toEqual(['override@example.net'])
        expect((await destinationStorage.getAll())[0]?.envelope.to[0]?.address).toBe(
          'override@example.net'
        )

        await destination.stop()
        destination = undefined
        const failedRelay = await server.server.inject({
          method: 'POST',
          url: `${alphaPath}/api/email/alpha-mail/relay/failed@example.net`,
          headers: { host: selectedHost },
        })
        expect(failedRelay.statusCode).toBe(500)
        expect((await alpha.getById('alpha-mail'))?.to).toEqual([
          { address: 'recipient@example.com' },
        ])
        expect((await alpha.getById('alpha-mail'))?.relayedTo).toEqual(['override@example.net'])

        const reload = vi.spyOn(source, 'loadMailsFromDirectory')
        const reloaded = await server.server.inject({
          method: 'GET',
          url: `${alphaPath}/api/reloadMailsFromDirectory`,
          headers: { host: selectedHost },
        })
        expect(reloaded.statusCode).toBe(200)
        expect(reload).toHaveBeenCalledWith('alpha.test')
      } finally {
        await source?.stop()
        await destination?.stop()
        await destinationStorage.close()
        await rm(mailDir, { recursive: true, force: true })
        await rm(destinationDir, { recursive: true, force: true })
      }
    }
  )
})
