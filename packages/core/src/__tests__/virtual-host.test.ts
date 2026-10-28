import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { VirtualHostStorage } from '../storage/virtual-host.js'
import type { Email } from '../types/index.js'
import { normalizeVirtualHost } from '../utils/virtual-host.js'

function makeEmail(id: string, host: string): Email {
  return {
    id,
    time: new Date(),
    read: false,
    subject: `Mail for ${host}`,
    source: `/tmp/${id}.eml`,
    size: 1,
    sizeHuman: '1 B',
    from: [],
    to: [],
    headers: {},
    attachments: [],
    envelope: { from: { address: '' }, to: [], host },
  }
}

describe('normalizeVirtualHost', () => {
  it('normalizes case and removes the optional port and trailing dot', () => {
    expect(normalizeVirtualHost('Alpha.Test.:1080')).toBe('alpha.test')
  })

  it('rejects values that could be used as filesystem paths', () => {
    expect(() => normalizeVirtualHost('../outside')).toThrow('Invalid virtual host')
    expect(() => normalizeVirtualHost('alpha.test/path')).toThrow('Invalid virtual host')
  })
})

describe('VirtualHostStorage', () => {
  let mailDirectory: string
  let storage: VirtualHostStorage

  afterEach(async () => {
    await storage?.close()
    if (mailDirectory) {
      await rm(mailDirectory, { recursive: true, force: true })
    }
  })

  it('isolates identical email IDs and persists each host under its own directory', async () => {
    mailDirectory = await mkdtemp(join(tmpdir(), 'maildev-vhosts-'))
    storage = new VirtualHostStorage({ mailDirectory })
    await storage.initialize()

    const alpha = storage.forHost('alpha.test:1080')!
    const beta = storage.forHost('beta.test')!
    await alpha.initialize()
    await beta.initialize()
    await alpha.save(makeEmail('same-id', 'alpha.test'))
    await beta.save(makeEmail('same-id', 'beta.test'))

    expect((await alpha.getById('same-id'))?.subject).toBe('Mail for alpha.test')
    expect((await beta.getById('same-id'))?.subject).toBe('Mail for beta.test')
    expect((await storage.forHost('alpha.test')!.getById('same-id'))?.source).toBe(
      join(mailDirectory, 'alpha.test', 'same-id.eml')
    )

    await writeFile(join(mailDirectory, 'alpha.test', 'same-id.eml'), 'mail')
    await storage.close()
    storage = new VirtualHostStorage({ mailDirectory })
    await storage.initialize()

    expect(await storage.getHosts()).toContain('alpha.test')
    expect(await readdir(join(mailDirectory, 'alpha.test'))).toContain('same-id.eml')
  })

  it('does not accept a host that could escape the mail directory', () => {
    storage = new VirtualHostStorage()
    expect(() => storage.forHost('../../outside')).toThrow('Invalid virtual host')
  })

  it('unsubscribes eviction handlers from hosts opened after registration', async () => {
    storage = new VirtualHostStorage({ maxEmails: 1 })
    const handler = vi.fn()
    const unsubscribe = storage.onEvicted(handler)
    const alpha = storage.forHost('alpha.test')
    await alpha.save(makeEmail('first', 'alpha.test'))
    await alpha.save(makeEmail('second', 'alpha.test'))
    expect(handler).toHaveBeenCalledTimes(1)

    unsubscribe()
    await alpha.save(makeEmail('third', 'alpha.test'))
    expect(handler).toHaveBeenCalledTimes(1)
  })
})
