import { mkdir, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import type {
  Email,
  EmailMetadata,
  RelayHistoryEntry,
  EvictHandler,
  ListOptions,
  ListResult,
  Storage,
  StorageOptions,
  StorageQuery,
  StorageStats,
} from '../types/index.js'
import { normalizeVirtualHost } from '../utils/virtual-host.js'
import { FileStorage } from './file.js'
import { MemoryStorage } from './memory.js'

/**
 * A storage registry that keeps each SMTP/HTTP host in its own inbox
 */
export class VirtualHostStorage implements Storage {
  readonly options: StorageOptions
  private readonly stores = new Map<string, Storage>()
  private readonly evictionHandlers = new Map<EvictHandler, Map<Storage, () => void>>()

  constructor(options: StorageOptions = {}) {
    this.options = { ...options, maxEmails: options.maxEmails ?? 0 }
  }

  /** Get the storage partition for an SMTP EHLO name or HTTP Host header */
  forHost(host: string): Storage {
    const normalizedHost = normalizeVirtualHost(host)
    const maxEmails = this.options.maxEmails ?? 0
    const existing = this.stores.get(normalizedHost)
    if (existing) {
      return existing
    }

    const storage = this.options.mailDirectory
      ? new FileStorage({
          mailDirectory: join(this.options.mailDirectory, encodeURIComponent(normalizedHost)),
          maxEmails,
        })
      : new MemoryStorage({ maxEmails })

    this.stores.set(normalizedHost, storage)
    for (const [handler, unsubscribers] of this.evictionHandlers) {
      unsubscribers.set(storage, storage.onEvicted(handler))
    }
    return storage
  }

  /** Return the partitions already opened or discovered on disk */
  async getHosts(): Promise<string[]> {
    return [...this.stores.keys()]
  }

  async getAll(): Promise<Email[]> {
    return this.defaultStorage().getAll()
  }

  async getById(id: string): Promise<Email | undefined> {
    return this.defaultStorage().getById(id)
  }

  async save(email: Email): Promise<void> {
    return this.defaultStorage().save(email)
  }

  async recordRelay(id: string, relay: RelayHistoryEntry): Promise<Email | undefined> {
    return this.defaultStorage().recordRelay(id, relay)
  }

  async delete(id: string): Promise<boolean> {
    return this.defaultStorage().delete(id)
  }

  async deleteAll(): Promise<number> {
    return this.defaultStorage().deleteAll()
  }

  async markAllRead(): Promise<number> {
    return this.defaultStorage().markAllRead()
  }

  async filter(query: StorageQuery): Promise<Email[]> {
    return this.defaultStorage().filter(query)
  }

  async list(options?: ListOptions): Promise<ListResult<Email>> {
    return this.defaultStorage().list(options)
  }

  async count(): Promise<number> {
    return this.defaultStorage().count()
  }

  async stats(): Promise<StorageStats> {
    return this.defaultStorage().stats()
  }

  onEvicted(handler: EvictHandler): () => void {
    const unsubscribers = new Map(
      [...this.stores.values()].map((storage) => [storage, storage.onEvicted(handler)])
    )
    this.evictionHandlers.set(handler, unsubscribers)

    return () => {
      this.evictionHandlers.delete(handler)
      unsubscribers.forEach((unsubscribe) => unsubscribe())
      unsubscribers.clear()
    }
  }

  async readMetadata(id: string): Promise<EmailMetadata | null> {
    return this.defaultStorage().readMetadata?.(id) ?? null
  }

  async initialize(): Promise<void> {
    if (this.options.mailDirectory) {
      await mkdir(this.options.mailDirectory, { recursive: true })
      const entries = await readdir(this.options.mailDirectory, { withFileTypes: true })
      for (const entry of entries) {
        if (!entry.isDirectory()) {
          continue
        }

        let host: string
        try {
          host = normalizeVirtualHost(decodeURIComponent(entry.name))
        } catch {
          continue
        }

        if (encodeURIComponent(host) !== entry.name) {
          continue
        }

        const files = await readdir(join(this.options.mailDirectory, entry.name), {
          withFileTypes: true,
        })
        if (
          files.some(
            (file) =>
              file.isFile() &&
              (file.name.endsWith('.eml') ||
                file.name.endsWith('.evl') ||
                file.name.endsWith('.meta.json'))
          )
        ) {
          await this.forHost(host).initialize()
        }
      }
    }

    await this.defaultStorage().initialize()
  }

  async close(): Promise<void> {
    await Promise.all([...this.stores.values()].map((storage) => storage.close()))
    for (const unsubscribers of this.evictionHandlers.values()) {
      unsubscribers.forEach((unsubscribe) => unsubscribe())
    }
    this.evictionHandlers.clear()
    this.stores.clear()
  }

  private defaultStorage(): Storage {
    return this.forHost('default')
  }
}
