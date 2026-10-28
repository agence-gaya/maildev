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

  it('binds MCP sessions to the host that created them', async () => {
    storage = new VirtualHostStorage()
    await storage.initialize()
    server = createAPIServer({
      storage,
      port: 0,
      virtualHost: true,
      mcp: { enabled: true },
    })
    await server.start()

    const init = await server.server.inject({
      method: 'POST',
      url: '/mcp',
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
      url: '/mcp',
      headers: {
        host: 'beta.test',
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'mcp-session-id': init.headers['mcp-session-id'] as string,
      },
      payload: { jsonrpc: '2.0', id: 2, method: 'ping' },
    })
    expect(crossHost.statusCode).toBe(400)
  })

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

      expect(targeted).toHaveBeenNthCalledWith(1, 'virtual-host:alpha.test')
      expect(targeted).toHaveBeenNthCalledWith(2, 'virtual-host:alpha.test')
      expect(broadcast).not.toHaveBeenCalled()
    } finally {
      await source.stop()
      await rm(mailDir, { recursive: true, force: true })
    }
  })

  it('relays a virtual-host email to an override without changing its stored recipients', async () => {
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
      email.attachments = [{
        filename: 'attachment.txt',
        generatedFileName: 'attachment.txt',
        contentType: 'text/plain',
        contentDisposition: 'attachment',
      }]
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
      await writeFile(join(mailDir, 'alpha.test', 'alpha-mail', 'attachment.txt'), 'attachment body')

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

      server = createAPIServer({ storage, smtp: source, virtualHost: true, port: 0 })
      await server.start()

      const attachment = await server.server.inject({
        method: 'GET',
        url: '/api/email/alpha-mail/attachment/attachment.txt',
        headers: { host: 'alpha.test' },
      })
      expect(attachment.statusCode).toBe(200)
      expect(attachment.body).toBe('attachment body')

      for (const path of ['source', 'attachment/attachment.txt']) {
        const crossHostDownload = await server.server.inject({
          method: 'GET',
          url: `/api/email/alpha-mail/${path}`,
          headers: { host: 'beta.test' },
        })
        expect(crossHostDownload.statusCode).toBe(404)
      }

      const crossHostRelay = await server.server.inject({
        method: 'POST',
        url: '/api/email/alpha-mail/relay/override@example.net',
        headers: { host: 'beta.test' },
      })
      expect(crossHostRelay.statusCode).toBe(500)
      expect(await destinationStorage.count()).toBe(0)

      const response = await server.server.inject({
        method: 'POST',
        url: '/api/email/alpha-mail/relay/override@example.net',
        headers: { host: 'alpha.test' },
      })

      expect(response.statusCode).toBe(200)
      const original = await alpha.getById('alpha-mail')
      expect(original?.to).toEqual([{ address: 'recipient@example.com' }])
      expect(original?.envelope.to).toEqual([{ address: 'recipient@example.com' }])
      expect(original?.relayedTo).toEqual(['override@example.net'])
      expect((await destinationStorage.getAll())[0]?.envelope.to[0]?.address).toBe('override@example.net')

      await destination.stop()
      destination = undefined
      const failedRelay = await server.server.inject({
        method: 'POST',
        url: '/api/email/alpha-mail/relay/failed@example.net',
        headers: { host: 'alpha.test' },
      })
      expect(failedRelay.statusCode).toBe(500)
      expect((await alpha.getById('alpha-mail'))?.to).toEqual([{ address: 'recipient@example.com' }])
      expect((await alpha.getById('alpha-mail'))?.relayedTo).toEqual(['override@example.net'])
    } finally {
      await source?.stop()
      await destination?.stop()
      await destinationStorage.close()
      await rm(mailDir, { recursive: true, force: true })
      await rm(destinationDir, { recursive: true, force: true })
    }
  })
})
