import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import nodemailer from 'nodemailer'
import { VirtualHostStorage, normalizeVirtualHost } from '@maildev/core'
import { SMTPServer } from '../server.js'

describe('SMTP virtual hosts', () => {
  let mailDir: string
  let storage: VirtualHostStorage
  let server: SMTPServer

  async function send(host: string, bcc?: string): Promise<void> {
    const transport = nodemailer.createTransport({
      host: '127.0.0.1',
      port: server.getPort(),
      name: host,
      secure: false,
    })
    try {
      await transport.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        ...(bcc ? { bcc } : {}),
        subject: `Message for ${host}`,
        text: 'Test message',
      })
    } finally {
      transport.close()
    }
  }

  async function startServer(options: { domainFilterRules?: { allow?: string; deny?: string }[] } = {}): Promise<void> {
    server = new SMTPServer({
      storage,
      mailDir,
      port: 0,
      host: '127.0.0.1',
      virtualHost: true,
      logger: false,
      ...options,
    })
    await server.start()
  }

  beforeEach(async () => {
    mailDir = await mkdtemp(join(tmpdir(), 'maildev-virtual-host-'))
    storage = new VirtualHostStorage({ mailDirectory: mailDir })
    await storage.initialize()
    await startServer()
  })

  afterEach(async () => {
    await server?.stop()
    await storage?.close()
    await rm(mailDir, { recursive: true, force: true })
  })

  it('stores messages and their raw files in the EHLO host inbox', async () => {
    await send('alpha.example.test')
    await send('beta.example.test')

    const alpha = await storage.forHost('alpha.example.test').getAll()
    const beta = await storage.forHost('beta.example.test').getAll()
    expect(alpha).toHaveLength(1)
    expect(beta).toHaveLength(1)
    expect(alpha[0]?.envelope.host).toBe('alpha.example.test')
    expect(beta[0]?.envelope.host).toBe('beta.example.test')
    expect(alpha[0]?.source).toBe(join(mailDir, 'alpha.example.test', `${alpha[0]?.id}.eml`))
    expect(existsSync(alpha[0]!.source)).toBe(true)
    expect(existsSync(beta[0]!.source)).toBe(true)
  })

  it('restores each virtual inbox from its own directory without relaying restored mail', async () => {
    await send('alpha.example.test', 'hidden@example.com')
    const original = (await storage.forHost('alpha.example.test').getAll())[0]!
    const envelopePath = join(mailDir, 'alpha.example.test', `${original.id}.evl`)
    expect(existsSync(envelopePath)).toBe(true)
    expect(JSON.parse(await readFile(envelopePath, 'utf8'))).toEqual(original.envelope)

    await server.stop()
    await storage.close()

    storage = new VirtualHostStorage({ mailDirectory: mailDir })
    await storage.initialize()
    await startServer()
    server.setupRelay({ host: '127.0.0.1', port: 9 })
    server.setAutoRelay({ enabled: true })
    const relay = vi.spyOn(server, 'relayEmail')
    await server.loadMailsFromDirectory()

    const restored = await storage.forHost('alpha.example.test').getAll()
    expect(restored).toHaveLength(1)
    expect(restored[0]?.envelope).toEqual(original.envelope)
    expect(restored[0]?.envelope.to.map(({ address }) => address)).toEqual([
      'recipient@example.com',
      'hidden@example.com',
    ])
    expect(restored[0]?.read).toBe(true)
    expect(await storage.forHost('beta.example.test').count()).toBe(0)
    expect(relay).not.toHaveBeenCalled()
  })

  it('uses the virtual inbox directory instead of a mismatching host in .evl', async () => {
    await send('alpha.example.test')
    const [email] = await storage.forHost('alpha.example.test').getAll()
    const envelopePath = join(mailDir, 'alpha.example.test', `${email!.id}.evl`)
    await writeFile(
      envelopePath,
      JSON.stringify({
        from: { address: 'sender@example.com' },
        to: [{ address: 'recipient@example.com' }],
        host: 'beta.example.test',
        remoteAddress: '192.0.2.1',
      })
    )

    await server.stop()
    await storage.close()
    storage = new VirtualHostStorage({ mailDirectory: mailDir })
    await storage.initialize()
    server = new SMTPServer({
      storage,
      mailDir,
      port: 0,
      host: '127.0.0.1',
      virtualHost: true,
      logger: false,
    })
    await server.loadMailsFromDirectory()

    expect((await storage.forHost('alpha.example.test').getById(email!.id))?.envelope.host)
      .toBe('alpha.example.test')
    expect((await storage.forHost('alpha.example.test').getById(email!.id))?.envelope.remoteAddress)
      .toBe('192.0.2.1')
    expect(await storage.forHost('beta.example.test').count()).toBe(0)
  })

  it('applies ordered domain rules to the SMTP EHLO name', async () => {
    await server.stop()
    server = new SMTPServer({
      storage,
      mailDir,
      port: 0,
      host: '127.0.0.1',
      virtualHost: true,
      domainFilterRules: [{ deny: '*' }, { allow: '*.allowed.test' }],
      logger: false,
    })
    await server.start()

    await expect(send('client.allowed.test')).resolves.toBeUndefined()
    await expect(send('blocked.test')).rejects.toThrow()
    expect(await storage.forHost('client.allowed.test').count()).toBe(1)
    expect(await storage.forHost('blocked.test').count()).toBe(0)
  })

  it('deletes expired emails only from their own virtual host', async () => {
    await send('alpha.example.test')
    await send('beta.example.test')

    const alphaStorage = storage.forHost('alpha.example.test')
    const alpha = (await alphaStorage.getAll())[0]!
    const envelopePath = join(mailDir, 'alpha.example.test', `${alpha.id}.evl`)
    expect(existsSync(envelopePath)).toBe(true)
    alpha.time = new Date(Date.now() - 48 * 60 * 60 * 1000)
    await alphaStorage.save(alpha)

    expect(await server.deleteOldEmails(24)).toBe(1)
    expect(await alphaStorage.count()).toBe(0)
    expect(await storage.forHost('beta.example.test').count()).toBe(1)
    expect(existsSync(alpha.source)).toBe(false)
    expect(existsSync(envelopePath)).toBe(false)
  })

  it('normalizes HTTP-compatible host names before routing storage', () => {
    expect(normalizeVirtualHost('Alpha.Example.Test:1080')).toBe('alpha.example.test')
  })
})
