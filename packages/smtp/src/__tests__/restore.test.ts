import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile, utimes } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MemoryStorage } from '@maildev/core'
import { SMTPServer } from '../server.js'

const EML = [
  'From: Angelo Pappas <angelo.pappas@fbi.gov>',
  'To: Johnny Utah <johnny.utah@fbi.gov>',
  'Subject: The ex-presidents are surfers',
  'Message-ID: <restore-test@example.com>',
  'Date: Mon, 27 Jul 2026 19:46:05 +0000',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'The wax at the bank was surfer wax!!!',
  '',
].join('\r\n')

describe('loadMailsFromDirectory', () => {
  let mailDir: string
  let storage: MemoryStorage
  let server: SMTPServer

  beforeEach(async () => {
    mailDir = await mkdtemp(join(tmpdir(), 'maildev-restore-'))
    storage = new MemoryStorage()
    await storage.initialize()
    server = new SMTPServer({ storage, mailDir })
  })

  afterEach(async () => {
    await rm(mailDir, { recursive: true, force: true })
  })

  it('restores emails persisted as .eml files into storage', async () => {
    await writeFile(join(mailDir, 'abc12345.eml'), EML)

    expect(await storage.getAll()).toHaveLength(0)

    await server.loadMailsFromDirectory()

    const emails = await storage.getAll()
    expect(emails).toHaveLength(1)
    expect(emails[0]?.id).toBe('abc12345')
    expect(emails[0]?.subject).toBe('The ex-presidents are surfers')
  })

  it('restores the historical SMTP envelope from an .evl file', async () => {
    const envelope = {
      from: { address: 'test@test1.maildev.local', args: false },
      to: [{ address: 'jliebert@gaya.fr', args: false }],
      host: 'test1.maildev.local',
      remoteAddress: '172.17.13.1',
    }
    await writeFile(join(mailDir, 'legacy.eml'), EML)
    await writeFile(join(mailDir, 'legacy.evl'), JSON.stringify(envelope))

    await server.loadMailsFromDirectory()

    expect((await storage.getById('legacy'))?.envelope).toEqual(envelope)
  })

  it('falls back to the parsed message when an .evl file is corrupt', async () => {
    await writeFile(join(mailDir, 'corrupt.eml'), EML)
    await writeFile(join(mailDir, 'corrupt.evl'), '{invalid json')
    await writeFile(join(mailDir, 'invalid-shape.eml'), EML)
    await writeFile(join(mailDir, 'invalid-shape.evl'), JSON.stringify({ from: 'bad', to: [] }))

    await server.loadMailsFromDirectory()

    for (const id of ['corrupt', 'invalid-shape']) {
      const email = await storage.getById(id)
      expect(email?.envelope.from).toEqual({ address: 'angelo.pappas@fbi.gov' })
      expect(email?.envelope.to).toEqual([{ address: 'johnny.utah@fbi.gov' }])
      expect(email?.envelope.remoteAddress).toBe('restored')
    }
  })

  it('ignores non-.eml files', async () => {
    await writeFile(join(mailDir, 'notes.txt'), 'not an email')
    await writeFile(join(mailDir, 'valid.eml'), EML)

    await server.loadMailsFromDirectory()

    const emails = await storage.getAll()
    expect(emails).toHaveLength(1)
    expect(emails[0]?.id).toBe('valid')
  })

  it('removes orphaned sidecars without touching associated or unrelated files', async () => {
    await writeFile(join(mailDir, 'valid.eml'), EML)
    await writeFile(join(mailDir, 'valid.evl'), '{}')
    await writeFile(join(mailDir, 'valid.meta.json'), '{}')
    await writeFile(join(mailDir, 'orphan.evl'), '{}')
    await writeFile(join(mailDir, 'orphan.meta.json'), '{}')
    await writeFile(join(mailDir, 'notes.txt'), 'keep')
    await mkdir(join(mailDir, 'directory.evl'))
    await symlink(join(mailDir, 'notes.txt'), join(mailDir, 'linked.evl'))

    await server.loadMailsFromDirectory()

    const files = await readdir(mailDir)
    expect(files).toContain('valid.evl')
    expect(files).toContain('valid.meta.json')
    expect(files).not.toContain('orphan.evl')
    expect(files).not.toContain('orphan.meta.json')
    expect(files).toContain('notes.txt')
    expect(files).toContain('directory.evl')
    expect(files).toContain('linked.evl')
  })

  it('keeps sidecars for emails outside the maxEmails restore limit', async () => {
    storage = new MemoryStorage({ maxEmails: 1 })
    await storage.initialize()
    server = new SMTPServer({ storage, mailDir })

    const oldPath = join(mailDir, 'old.eml')
    const newPath = join(mailDir, 'new.eml')
    await writeFile(oldPath, EML)
    await writeFile(newPath, EML)
    const oldTime = new Date('2020-01-01T00:00:00.000Z')
    const newTime = new Date('2025-01-01T00:00:00.000Z')
    await utimes(oldPath, oldTime, oldTime)
    await utimes(newPath, newTime, newTime)
    await writeFile(join(mailDir, 'old.evl'), '{}')
    await writeFile(join(mailDir, 'old.meta.json'), '{}')

    await server.loadMailsFromDirectory()

    expect((await storage.getAll()).map((email) => email.id)).toEqual(['new'])
    const files = await readdir(mailDir)
    expect(files).toContain('old.evl')
    expect(files).toContain('old.meta.json')
  })

  it('restores an email without a From header', async () => {
    await writeFile(
      join(mailDir, 'no-from.eml'),
      'To: recipient@example.com\r\nSubject: No sender\r\n\r\nBody\r\n'
    )

    await server.loadMailsFromDirectory()

    const email = await storage.getById('no-from')
    expect(email?.from).toEqual([])
    expect(email?.envelope.from.address).toBe('')
  })

  it('keeps the file timestamp when a restored email has no Date header', async () => {
    const receivedAt = new Date('2020-01-02T03:04:05.000Z')
    const path = join(mailDir, 'no-date.eml')
    await writeFile(path, 'From: sender@example.com\r\nSubject: No date\r\n\r\nBody\r\n')
    await utimes(path, receivedAt, receivedAt)

    await server.loadMailsFromDirectory()

    expect((await storage.getById('no-date'))?.time).toEqual(receivedAt)
  })

  it('does not throw when the mail directory has no emails', async () => {
    await expect(server.loadMailsFromDirectory()).resolves.toBeUndefined()
    expect(await storage.getAll()).toHaveLength(0)
  })
})
