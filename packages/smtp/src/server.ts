/**
 * @maildev/smtp - SMTP Server
 *
 * Modern TypeScript SMTP server with async/await patterns.
 */

import { SMTPServer as SMTPServerLib } from 'smtp-server'
import type { SMTPServerSession, SMTPServerDataStream } from 'smtp-server'
import { EventEmitter } from 'node:events'
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { mkdir, rm, readdir, readFile, writeFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { PassThrough, Transform, type Readable } from 'node:stream'
import { formatBytes, calculateBcc, makeId, mapLimit, normalizeVirtualHost, type Storage, type Email, type EmailMetadata, type Attachment } from '@maildev/core'
import { parseEmailStream, parseEmailBuffer } from './parser.js'
import { createAuthCallback } from './auth.js'
import { createLogger } from './logger.js'
import { sanitizeHtml, replaceCidReferences } from './sanitize.js'
import { transformAttachment, getAttachmentFilePath, getAttachmentDir } from './attachments.js'
import { RelayClient } from './relay.js'
import type {
  SMTPServerOptions,
  StoredEnvelope,
  ParsedEmail,
  ParsedAttachment,
  HideableExtension,
  DomainFilterRule,
  RelayConfig,
  AutoRelayConfig,
  Logger,
  HTMLRenderOptions,
  EmailDownload,
  EnvelopeAddress,
  TransformedAttachment,
} from './types.js'

const DEFAULT_PORT = 1025
const DEFAULT_HOST = '::'

/** Cap on concurrent filesystem operations, to stay well clear of EMFILE */
const FS_CONCURRENCY = 16

/** How many emails to parse before saving them, when restoring from disk */
const RESTORE_CHUNK_SIZE = 64
const HOUR_MS = 60 * 60 * 1000

function matchesDomainRules(host: string, rules: DomainFilterRule[]): boolean {
  let result = true
  for (const rule of rules) {
    const pattern = rule.allow || rule.deny || ''
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
    if (new RegExp(`^${escaped}$`, 'i').test(host)) {
      result = Boolean(rule.allow)
    }
  }
  return result
}

/** An .eml file found in the mail directory */
interface EmlFile {
  /** Email ID, i.e. the filename without the .eml suffix */
  id: string
  /** Last modified time, used to order the directory newest-first */
  mtimeMs: number
}

const HIDEABLE_EXTENSIONS: HideableExtension[] = [
  'STARTTLS',
  'PIPELINING',
  '8BITMIME',
  'SMTPUTF8',
]

/**
 * MailDev SMTP Server
 *
 * Receives emails via SMTP and stores them using the provided storage backend.
 */
export class SMTPServer extends EventEmitter {
  private smtp: SMTPServerLib | null = null
  private storage: Storage
  private mailDir: string
  private port: number
  private host: string
  private options: SMTPServerOptions
  private logger: Logger
  private relayClient: RelayClient | null = null
  private unsubscribeEvict: () => void
  private autoDeleteTimer: NodeJS.Timeout | null = null
  private autoDeleteTask: Promise<number> | null = null

  constructor(options: SMTPServerOptions) {
    super()

    this.storage = options.storage
    this.mailDir = options.mailDir
    // Use ?? so an explicit `port: 0` (bind an OS-assigned ephemeral port) is
    // honored rather than falling back to the default — `0 || DEFAULT` would
    // treat a meaningful 0 as absent. The real port is read back from the
    // listening socket in start() and exposed via getAddress()/getPort().
    this.port = options.port ?? DEFAULT_PORT
    this.host = options.host || DEFAULT_HOST
    this.options = options
    this.logger = createLogger(options.logger)

    if (options.virtualHost && !options.storage.forHost) {
      throw new Error('Virtual host mode requires a host-aware storage backend')
    }

    // Ensure mail directory exists
    this.ensureMailDir()

    // We wrote the .eml and attachments, so we clean them up when the store
    // drops an email to stay within its limit. Otherwise the store stays
    // bounded while the directory on disk grows forever.
    this.unsubscribeEvict = this.storage.onEvicted((email) =>
      this.removeEmailFiles(email.id, email.envelope.host)
    )
  }

  /**
   * Start the SMTP server
   */
  async start(): Promise<void> {
    // Build smtp-server configuration
    const config = this.buildServerConfig()

    this.smtp = new SMTPServerLib(config)

    // Node's server.listen() callback is the 'listening' listener, not an
    // error-first callback. Bind failures (EADDRINUSE, EACCES, …) arrive on
    // 'error' instead, so reject start() from that event until we are listening.
    return new Promise((resolve, reject) => {
      const onStartupError = (err: Error) => {
        reject(err)
      }
      this.smtp!.once('error', onStartupError)

      this.smtp!.listen(this.port, this.host, (err?: Error) => {
        if (err) {
          this.smtp!.off('error', onStartupError)
          reject(err)
          return
        }

        this.smtp!.off('error', onStartupError)
        this.smtp!.on('error', (e: NodeJS.ErrnoException) => {
          this.handleServerError(e)
        })

        // Record the port the OS actually bound. When `port: 0` was requested
        // this is the assigned ephemeral port; getAddress()/getPort() then let
        // the caller discover it (e.g. one MailDev per parallel test worker).
        const address = this.smtp!.server.address()
        if (address && typeof address === 'object') {
          this.port = address.port
        }

        const printHost = this.host === '::' ? 'localhost' : this.host
        this.logger.info(`SMTP Server running at ${printHost}:${this.port}`)
        this.startAutoDelete()
        resolve()
      })
    })
  }

  /**
   * Get the address the SMTP server is bound to
   *
   * After start(), the port reflects the actual bound port — so a server
   * started with `port: 0` reports the OS-assigned ephemeral port here.
   */
  getAddress(): { host: string; port: number } {
    return { host: this.host, port: this.port }
  }

  /**
   * Get the port the SMTP server is bound to
   *
   * After start() with `port: 0`, this is the OS-assigned ephemeral port.
   */
  getPort(): number {
    return this.port
  }

  /**
   * Stop the SMTP server
   */
  async stop(): Promise<void> {
    this.emit('close')

    if (this.autoDeleteTimer) {
      clearInterval(this.autoDeleteTimer)
      this.autoDeleteTimer = null
    }
    await this.autoDeleteTask

    this.unsubscribeEvict()

    if (this.relayClient) {
      await this.relayClient.close()
    }

    return new Promise((resolve) => {
      if (this.smtp) {
        this.smtp.close(() => resolve())
      } else {
        resolve()
      }
    })
  }

  /**
   * Configure outgoing relay
   */
  setupRelay(config: RelayConfig): void {
    this.relayClient = new RelayClient(config, this.options.logger)
    this.logger.info(
      `Outgoing SMTP configured: ${config.host}:${config.port} (secure: ${config.secure ? 'yes' : 'no'})`
    )
  }

  /**
   * Check if relay is enabled
   */
  isRelayEnabled(): boolean {
    return this.relayClient !== null
  }

  /**
   * Get the outgoing relay host
   */
  getRelayHost(): string | undefined {
    return this.relayClient?.getHost()
  }

  /**
   * Configure auto-relay
   */
  setAutoRelay(config: AutoRelayConfig): void {
    if (!this.relayClient) {
      this.logger.warn('Outgoing mail not configured - Auto relay mode ignored')
      return
    }
    this.relayClient.setAutoRelay(config)
  }

  /**
   * Check if auto-relay is enabled
   */
  isAutoRelayEnabled(): boolean {
    return this.relayClient?.isAutoRelayEnabled() ?? false
  }

  /**
   * Get an email by ID
   */
  async getEmail(id: string, host?: string): Promise<Email> {
    const email = await this.storageForHost(host).getById(id)
    if (!email) {
      throw new Error('Email was not found')
    }

    // Sanitize HTML content
    if (email.html) {
      const sanitized = sanitizeHtml(email.html)
      if (sanitized) {
        email.html = sanitized
      }
    }

    return email
  }

  /**
   * Get an email's HTML content with embedded attachments resolved
   */
  async getEmailHtml(
    id: string,
    options: HTMLRenderOptions = {},
    host?: string
  ): Promise<string | undefined> {
    const email = await this.getEmail(id, host)

    if (!email.html) {
      return undefined
    }

    let html = email.html

    // Replace CID references with actual URLs
    if (email.attachments && email.attachments.length > 0) {
      html = replaceCidReferences(html, id, email.attachments, options.baseUrl, options.basePath)
    }

    return html
  }

  /**
   * Get a readable stream of the raw .eml file
   */
  async getRawEmail(id: string, host?: string): Promise<Readable> {
    const email = await this.getEmail(id, host)
    return createReadStream(join(this.mailDirectoryForHost(email.envelope.host ?? host), `${email.id}.eml`))
  }

  /**
   * Get all emails
   */
  async getAllEmails(host?: string): Promise<Email[]> {
    return this.storageForHost(host).getAll()
  }

  /**
   * Mark all emails as read
   */
  async markAllRead(host?: string): Promise<number> {
    return this.storageForHost(host).markAllRead()
  }

  /**
   * Delete an email by ID
   */
  async deleteEmail(id: string, host?: string): Promise<boolean> {
    const storage = this.storageForHost(host)
    const email = await storage.getById(id)
    if (!email) {
      throw new Error('Email not found')
    }

    await this.removeEmailFiles(id, email.envelope.host ?? host)

    this.logger.warn('Deleting email -', email.subject)

    const result = await storage.delete(id)
    if (result) {
      this.emit('delete', {
        id,
        ...(this.options.virtualHost ? { host: normalizeVirtualHost(email.envelope.host ?? host) } : {}),
      })
    }

    return result
  }

  /**
   * Delete all emails
   */
  async deleteAllEmails(host?: string): Promise<number> {
    this.logger.warn('Deleting all emails')

    await this.clearMailDir(host)
    const count = await this.storageForHost(host).deleteAll()

    this.emit('delete', {
      id: 'all',
      ...(this.options.virtualHost ? { host: normalizeVirtualHost(host) } : {}),
    })

    return count
  }

  /**
   * Get an email attachment
   */
  async getEmailAttachment(
    id: string,
    filename: string,
    host?: string
  ): Promise<{ contentType: string; stream: Readable }> {
    const email = await this.getEmail(id, host)

    if (!email.attachments || email.attachments.length === 0) {
      throw new Error('Email has no attachments')
    }

    const attachment = email.attachments.find(
      (a) => a.generatedFileName === filename
    )

    if (!attachment) {
      throw new Error('Attachment not found')
    }

    // Build the transformed attachment object for file path lookup
    const transformedAttachment: TransformedAttachment = {
      filename: attachment.filename,
      generatedFileName: attachment.generatedFileName,
      contentType: attachment.contentType,
      contentDisposition: attachment.contentDisposition,
      contentId: attachment.contentId,
      size: attachment.size || 0,
      transformed: true,
    }

    const filePath = getAttachmentFilePath(
      this.mailDirectoryForHost(email.envelope.host ?? host),
      id,
      transformedAttachment
    )
    const stream = createReadStream(filePath)

    return {
      contentType: attachment.contentType,
      stream,
    }
  }

  /**
   * Download an email as .eml file
   */
  async downloadEmail(id: string, host?: string): Promise<EmailDownload> {
    const email = await this.getEmail(id, host) // Verify email exists

    return {
      contentType: 'message/rfc822',
      filename: `${id}.eml`,
      stream: createReadStream(join(this.mailDirectoryForHost(email.envelope.host ?? host), `${id}.eml`)),
    }
  }

  /**
   * Relay an email to the configured outgoing server
   */
  async relayEmail(idOrEmail: string | Email, isAutoRelay = false, host?: string): Promise<void> {
    if (!this.relayClient) {
      throw new Error('Outgoing mail not configured')
    }

    const email = typeof idOrEmail === 'string'
      ? await this.getEmail(idOrEmail, host)
      : idOrEmail

    const rawStream = await this.getRawEmail(email.id, email.envelope.host)
    const result = await this.relayClient.relay(email, rawStream, isAutoRelay)

    if (!result.success) {
      if (result.error) {
        throw result.error
      }
      return
    }

    // Record the successful relay on the stored email so the API and UI can
    // tell whether (and where) a message was delivered.
    const storage = this.storageForHost(email.envelope.host)
    const storedEmail = await storage.getById(email.id)
    if (!storedEmail) {
      return
    }
    storedEmail.relayedAt = new Date()
    storedEmail.relayedTo = result.recipients ?? []
    await storage.save(storedEmail)
  }

  /**
   * Load existing emails from the mail directory
   *
   * Only the newest `maxEmails` are restored — reading and parsing a directory
   * that has accumulated tens of thousands of messages would otherwise stall
   * startup and immediately blow past the store's limit anyway.
   */
  async loadMailsFromDirectory(host?: string): Promise<void> {
    const hosts = this.options.virtualHost
      ? host
        ? [normalizeVirtualHost(host)]
        : await this.storage.getHosts?.() ?? []
      : [undefined]

    for (const currentHost of hosts) {
      const storage = this.storageForHost(currentHost)
      if (this.options.virtualHost) {
        await storage.initialize()
      }
      await this.restoreMailDirectory(
        this.mailDirectoryForHost(currentHost),
        currentHost,
        storage
      )
    }
  }

  private async restoreMailDirectory(
    mailDir: string,
    host: string | undefined,
    storage: Storage
  ): Promise<void> {
    let files: EmlFile[]
    try {
      files = await this.listEmlFiles(mailDir)
    } catch (err) {
      this.logger.error('Error reading mail directory:', mailDir, err)
      return
    }

    const max = storage.options.maxEmails ?? 0
    const selected = max > 0 ? files.slice(0, max) : files

    if (selected.length < files.length) {
      this.logger.warn(
        `Restoring the ${selected.length} most recent of ${files.length} emails in ${mailDir}`
      )
    }

    // Reading and parsing dominates the cost, so a chunk at a time runs in
    // parallel; saving is cheap and happens in order afterwards. Working in
    // chunks rather than parsing the whole directory up front keeps only one
    // chunk of parsed emails in memory beyond the store itself.
    //
    // Oldest first, so arrival order — and therefore eviction order — matches
    // the order the emails were originally received.
    const ordered = [...selected].reverse()

    for (let offset = 0; offset < ordered.length; offset += RESTORE_CHUNK_SIZE) {
      const chunk = ordered.slice(offset, offset + RESTORE_CHUNK_SIZE)

      const parsedChunk = await mapLimit(chunk, FS_CONCURRENCY, async (file) => {
        try {
          const data = await readFile(join(mailDir, `${file.id}.eml`), 'utf8')
          this.logger.log('Restoring email:', file.id)
          return { id: file.id, parsed: await parseEmailBuffer(data) }
        } catch (err) {
          this.logger.error(`Error restoring email ${file.id}:`, err)
          return null
        }
      })

      for (const entry of parsedChunk) {
        if (!entry) {
          continue
        }

        const { id, parsed } = entry

        // Build envelope from parsed headers
        const envelope: StoredEnvelope = {
          from: parsed.from?.[0] ? { address: parsed.from[0].address } : false,
          to: (parsed.to || []).map((addr) => ({ address: addr.address })),
          host: host ?? 'restored',
          remoteAddress: 'restored',
        }

        try {
          // Restore any metadata persisted alongside the .eml.
          const metadata = await storage.readMetadata?.(id)
          await this.saveEmail(id, envelope, parsed, true, metadata, storage)
        } catch (err) {
          this.logger.error(`Error restoring email ${id}:`, err)
        }
      }
    }
  }

  /**
   * Delete the oldest .eml files so at most `keep` remain on disk
   *
   * Files outliving the emails they belong to is what makes a long-lived
   * MailDev slow to restart and eventually forces a manual wipe of the mail
   * directory. Running this at startup keeps that from happening.
   * @param keep - How many of the newest emails to retain (0 = keep everything)
   * @returns Number of emails removed from disk
   */
  async pruneMailDir(keep: number): Promise<number> {
    if (keep <= 0) {
      return 0
    }

    if (this.options.virtualHost) {
      const hosts = await this.storage.getHosts?.() ?? []
      let removed = 0
      for (const host of hosts) {
        removed += await this.pruneMailDirectory(this.mailDirectoryForHost(host), keep)
      }
      return removed
    }

    return this.pruneMailDirectory(this.mailDir, keep)
  }

  /** Delete emails whose received time is older than the configured age */
  async deleteOldEmails(maxAgeHours = this.options.autoDelete ?? 0): Promise<number> {
    if (maxAgeHours <= 0) {
      return 0
    }
    if (this.autoDeleteTask) {
      return this.autoDeleteTask
    }

    const task = (async () => {
      const cutoff = Date.now() - maxAgeHours * HOUR_MS
      const hosts = this.options.virtualHost
        ? await this.storage.getHosts?.() ?? []
        : [undefined]
      let deleted = 0

      for (const host of hosts) {
        const storage = this.storageForHost(host)
        const emails = await storage.getAll()
        for (const email of emails) {
          const receivedAt = new Date(email.time).getTime()
          if (Number.isFinite(receivedAt) && receivedAt < cutoff) {
            try {
              if (await this.deleteEmail(email.id, host)) {
                deleted++
              }
            } catch (error) {
              this.logger.warn(`Unable to delete expired email ${email.id}:`, error)
            }
          }
        }
      }

      return deleted
    })()

    this.autoDeleteTask = task
    try {
      return await task
    } finally {
      if (this.autoDeleteTask === task) {
        this.autoDeleteTask = null
      }
    }
  }

  private async pruneMailDirectory(mailDir: string, keep: number): Promise<number> {

    let files: EmlFile[]
    try {
      files = await this.listEmlFiles(mailDir)
    } catch (err) {
      this.logger.error('Error reading mail directory:', err)
      return 0
    }

    if (files.length <= keep) {
      return 0
    }

    const stale = files.slice(keep)
    await mapLimit(stale, FS_CONCURRENCY, (file) => this.removeEmailFiles(file.id, undefined, mailDir))

    this.logger.warn(
        `Removed ${stale.length} old email(s) from ${mailDir} (keeping the newest ${keep})`
    )

    return stale.length
  }

  /**
   * Build smtp-server configuration
   */
  private buildServerConfig(): Record<string, unknown> {
    const config: Record<string, unknown> = {
      secure: this.options.secure || false,
      onData: this.handleDataStream.bind(this),
      logger: false,
      hideSTARTTLS: true,
      disabledCommands: ['AUTH'] as string[],
    }

    // Advertise and enforce a maximum message size. smtp-server rejects
    // messages that declare an oversized SIZE at MAIL FROM, and flags the DATA
    // stream with `sizeExceeded` when the body itself runs over (see
    // processIncomingEmail). 0/undefined disables the limit.
    if (this.options.maxMessageSize && this.options.maxMessageSize > 0) {
      config.size = this.options.maxMessageSize
    }

    // Load TLS certificates
    if (this.options.certPath) {
      config.cert = readFileSync(this.options.certPath)
    }
    if (this.options.keyPath) {
      config.key = readFileSync(this.options.keyPath)
    }

    // Configure authentication
    if (this.options.auth) {
      config.onAuth = createAuthCallback(this.options.auth)
      config.disabledCommands = this.options.secure ? [] : ['STARTTLS']
    }

    // Hide extensions
    if (this.options.hideExtensions) {
      const hideOptions = this.getHideExtensionOptions(this.options.hideExtensions)
      Object.assign(config, hideOptions)
    }

    if (this.options.domainFilterRules) {
      config.onMailFrom = (
        _address: EnvelopeAddress,
        session: SMTPServerSession,
        callback: (error?: Error | null) => void
      ) => {
        const ehlo = session.hostNameAppearsAs
        if (!ehlo || !matchesDomainRules(ehlo, this.options.domainFilterRules!)) {
          callback(new Error('You are not allowed to send mail'))
          return
        }
        callback()
      }
    }

    return config
  }

  private startAutoDelete(): void {
    const hours = this.options.autoDelete ?? 0
    if (hours <= 0 || this.autoDeleteTimer) {
      return
    }

    const interval = Math.min(hours * HOUR_MS, HOUR_MS)
    this.autoDeleteTimer = setInterval(() => {
      void this.deleteOldEmails().catch((error) => {
        this.logger.error('Error deleting expired emails:', error)
      })
    }, interval)
    this.autoDeleteTimer.unref?.()
  }

  /**
   * Get hide extension options for smtp-server
   */
  private getHideExtensionOptions(
    extensions: HideableExtension[]
  ): Record<string, boolean> {
    const options: Record<string, boolean> = {}

    for (const ext of extensions) {
      const upperExt = ext.toUpperCase() as HideableExtension
      if (!HIDEABLE_EXTENSIONS.includes(upperExt)) {
        throw new Error(`Invalid hideable extension: ${ext}`)
      }
      options[`hide${upperExt}`] = true
    }

    return options
  }

  /**
   * Handle incoming email data stream
   */
  private handleDataStream(
    stream: SMTPServerDataStream,
    session: SMTPServerSession,
    callback: (err: Error | null, message?: string) => void
  ): void {
    // Process asynchronously but call callback synchronously as required by smtp-server
    this.processIncomingEmail(stream, session)
      .then((id) => callback(null, `Message queued as ${id}`))
      .catch((err) => callback(err))
  }

  /**
   * Process an incoming email
   */
  private async processIncomingEmail(
    stream: Readable,
    session: SMTPServerSession
  ): Promise<string> {
    const id = makeId()
    const host = this.options.virtualHost
      ? normalizeVirtualHost(session.hostNameAppearsAs)
      : session.hostNameAppearsAs
    const mailDir = this.mailDirectoryForHost(host)
    await mkdir(mailDir, { recursive: true })
    const emlPath = join(mailDir, `${id}.eml`)

    // Cap the bytes forwarded to the writer/parser at maxMessageSize. This
    // bounds the work spent parsing a single message regardless of how much
    // DATA the client actually sends, which is what stops a malicious multipart
    // body with a huge number of parts from tying up the parser. The cap keeps
    // draining the source after the limit (so the SMTP DATA command still
    // completes) and records that the message was truncated so it can be
    // rejected below. Well-behaved clients that declare an oversized SIZE are
    // already refused earlier by smtp-server's `size` option.
    const limit = this.options.maxMessageSize && this.options.maxMessageSize > 0
      ? this.options.maxMessageSize
      : 0
    const sizeState = { exceeded: false }
    const source = limit ? stream.pipe(this.createSizeCap(limit, sizeState)) : stream

    // Create two pass-through streams to duplicate the data
    const emlPassThrough = new PassThrough()
    const parsePassThrough = new PassThrough()

    // Pipe to both streams
    source.pipe(emlPassThrough)
    source.pipe(parsePassThrough)

    // Write to disk and parse in parallel
    const [, parsed] = await Promise.all([
      pipeline(emlPassThrough, createWriteStream(emlPath)),
      parseEmailStream(parsePassThrough),
    ])

    // Reject messages that ran past the size limit. The file only holds the
    // truncated prefix, so discard it and refuse the message rather than storing
    // a partial.
    if (sizeState.exceeded) {
      await rm(emlPath, { force: true })
      const error = new Error('Message exceeds maximum allowed size') as Error & { responseCode?: number }
      error.responseCode = 552 // permanent: exceeded storage allocation
      throw error
    }

    // Save attachments
    if (parsed.attachments && parsed.attachments.length > 0) {
      await this.saveAttachments(id, parsed.attachments, mailDir)
    }

    // Build envelope from session - convert smtp-server types to our types
    const sessionMailFrom = session.envelope.mailFrom
    const sessionRcptTo = session.envelope.rcptTo

    const envelope: StoredEnvelope = {
      from: sessionMailFrom
        ? { address: sessionMailFrom.address, args: sessionMailFrom.args as Record<string, string | boolean> | false }
        : false,
      to: (sessionRcptTo || []).map((addr) => ({
        address: addr.address,
        args: addr.args as Record<string, string | boolean> | false,
      })),
      host,
      remoteAddress: session.remoteAddress,
    }

    // Save email to storage
    const storage = this.storageForHost(host)
    await storage.initialize()
    await this.saveEmail(id, envelope, parsed, false, undefined, storage)

    return id
  }

  /**
   * Build a Transform that forwards at most `limit` bytes downstream and then
   * keeps draining its input (so the source stream can finish) while dropping
   * the excess. Sets `state.exceeded` once the limit is crossed.
   */
  private createSizeCap(limit: number, state: { exceeded: boolean }): Transform {
    let bytes = 0
    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        if (state.exceeded) {
          callback() // already over the limit: drain and drop
          return
        }
        bytes += chunk.length
        if (bytes > limit) {
          state.exceeded = true
          const allowed = chunk.length - (bytes - limit)
          callback(null, allowed > 0 ? chunk.subarray(0, allowed) : undefined)
          return
        }
        callback(null, chunk)
      },
    })
  }

  /**
   * Save an email to storage
   */
  private async saveEmail(
    id: string,
    envelope: StoredEnvelope,
    parsed: ParsedEmail,
    isRestored = false,
    metadata?: EmailMetadata | null,
    storage: Storage = this.storageForHost(envelope.host)
  ): Promise<Email> {
    const emlPath = join(this.mailDirectoryForHost(envelope.host), `${id}.eml`)
    const emlStat = await stat(emlPath)

    // Transform attachments for storage
    const transformedAttachments: Attachment[] = parsed.attachments
      ? parsed.attachments.map((att) => {
          const transformed = transformAttachment(att)
          // Build attachment object, only including optional fields if they have values
          const attachment: Attachment = {
            filename: transformed.filename,
            generatedFileName: transformed.generatedFileName,
            contentType: transformed.contentType,
            contentDisposition: transformed.contentDisposition,
          }
          if (transformed.contentId) {
            attachment.contentId = transformed.contentId
          }
          if (transformed.size !== undefined) {
            attachment.size = transformed.size
          }
          return attachment
        })
      : []

    // Calculate BCC recipients - pass Address arrays as required
    const envelopeToAddresses: string[] = (envelope.to || []).map((t) => {
      if (typeof t === 'string') return t
      return t.address
    })

    const toAddresses = parsed.to || []
    const ccAddresses = parsed.cc || []

    const calculatedBcc = calculateBcc(
      envelopeToAddresses,
      toAddresses,
      ccAddresses
    )

    // Build email object, only including optional fields if they have values
    const email: Email = {
      id,
      time: parsed.date || (isRestored ? emlStat.mtime : new Date()),
      read: isRestored,
      subject: parsed.subject || '',
      source: emlPath,
      size: emlStat.size,
      sizeHuman: formatBytes(emlStat.size),
      from: parsed.from || [],
      to: parsed.to || [],
      headers: this.headersToRecord(parsed.headers),
      attachments: transformedAttachments,
      envelope: {
        from: this.toEnvelopeAddress(envelope.from),
        to: envelope.to.map((t) => this.toEnvelopeAddress(t)),
        ...(envelope.host ? { host: envelope.host } : {}),
        ...(envelope.remoteAddress ? { remoteAddress: envelope.remoteAddress } : {}),
      },
      calculatedBcc,
    }

    // Add optional fields only if they have values
    if (parsed.cc && parsed.cc.length > 0) {
      email.cc = parsed.cc
    }
    if (parsed.html) {
      email.html = parsed.html
    }
    if (parsed.text) {
      email.text = parsed.text
    }
    if (parsed.inReplyTo) {
      email.inReplyTo = parsed.inReplyTo
    }
    if (parsed.priority) {
      email.priority = parsed.priority
    }

    // Carry forward metadata persisted in a previous session (restore only).
    if (metadata?.relayedAt) {
      email.relayedAt = metadata.relayedAt
      email.relayedTo = metadata.relayedTo ?? []
    }

    await storage.save(email)

    this.logger.log('Saved email:', parsed.subject, 'id:', id)

    // Auto-relay if enabled
    if (!isRestored && this.isAutoRelayEnabled()) {
      try {
        await this.relayEmail(email, true)
      } catch (err) {
        this.logger.error('Error during auto-relay:', err)
      }
    }

    if (!isRestored) {
      this.emit('new', email)
    }

    return email
  }

  /**
   * Convert envelope address to core format
   */
  private toEnvelopeAddress(
    addr: EnvelopeAddress | { address: string; args?: boolean | Record<string, unknown> } | false
  ): { address: string; args?: boolean | Record<string, unknown> } {
    if (addr === false) {
      return { address: '' }
    }
    // Only include args if it's truthy (not false or undefined)
    const result: { address: string; args?: boolean | Record<string, unknown> } = {
      address: addr.address,
    }
    if (addr.args) {
      result.args = addr.args as boolean | Record<string, unknown>
    }
    return result
  }

  /**
   * Save email attachments to disk
   */
  private async saveAttachments(
    emailId: string,
    attachments: ParsedAttachment[],
    mailDir: string
  ): Promise<void> {
    const attachDir = getAttachmentDir(mailDir, emailId)

    if (!existsSync(attachDir)) {
      mkdirSync(attachDir, { recursive: true })
    }

    for (const attachment of attachments) {
      if (!attachment.content) {
        continue
      }

      const transformed = transformAttachment(attachment)
      const filePath = getAttachmentFilePath(mailDir, emailId, transformed)

      await writeFile(filePath, new Uint8Array(attachment.content))
    }
  }

  /**
   * Convert headers Map to plain object
   */
  private headersToRecord(
    headers?: Map<string, string | string[]>
  ): Record<string, string | string[]> {
    if (!headers) {
      return {}
    }

    const result: Record<string, string | string[]> = {}
    headers.forEach((value, key) => {
      result[key] = value
    })
    return result
  }

  /**
   * Handle SMTP server errors
   */
  private handleServerError(err: NodeJS.ErrnoException): void {
    // ECONNRESET is common when clients disconnect unexpectedly
    if (err.code === 'ECONNRESET' && err.syscall === 'read') {
      this.logger.warn(
        `Ignoring "${err.message}" error - client likely disconnected`
      )
      this.logger.debug?.(err)
    } else {
      // Do not throw: this runs from an event callback, so a throw is uncaught
      // and kills the process. A bare emit('error') with no listener does too.
      this.logger.error(err.message)
      if (this.listenerCount('error') > 0) {
        this.emit('error', err)
      }
    }
  }

  /**
   * Ensure the mail directory exists
   */
  private ensureMailDir(): void {
    if (!existsSync(this.mailDir)) {
      mkdirSync(this.mailDir, { recursive: true })
    }
    this.logger.info('Using mail directory:', this.mailDir)
  }

  private storageForHost(host?: string): Storage {
    if (!this.options.virtualHost) {
      return this.storage
    }
    if (!this.storage.forHost) {
      throw new Error('Virtual host mode requires a host-aware storage backend')
    }
    return this.storage.forHost(host ?? '')
  }

  private mailDirectoryForHost(host?: string): string {
    return this.options.virtualHost
      ? join(this.mailDir, encodeURIComponent(normalizeVirtualHost(host)))
      : this.mailDir
  }

  /**
   * Clear all files in the mail directory
   */
  private async clearMailDir(host?: string): Promise<void> {
    const mailDir = this.mailDirectoryForHost(host)
    try {
      const files = await readdir(mailDir)

      // Bounded concurrency: an inbox with tens of thousands of emails would
      // otherwise try to unlink every file at once and hit EMFILE.
      await mapLimit(files, FS_CONCURRENCY, async (file) => {
        try {
          await rm(join(mailDir, file), { recursive: true, force: true })
        } catch (err) {
          this.logger.error('Error deleting file:', file, err)
        }
      })
    } catch (err) {
      this.logger.error('Error clearing mail directory:', err)
    }
  }

  /**
   * List the .eml files in the mail directory, newest first
   */
  private async listEmlFiles(mailDir = this.mailDir): Promise<EmlFile[]> {
    const entries = await readdir(mailDir, { withFileTypes: true })
    const emlEntries = entries.filter(
      (entry) => entry.isFile() && entry.name.endsWith('.eml')
    )

    const files = await mapLimit(emlEntries, FS_CONCURRENCY, async (entry) => {
      try {
        const info = await stat(join(mailDir, entry.name))
        return { id: entry.name.slice(0, -4), mtimeMs: info.mtimeMs }
      } catch {
        // Raced with a delete; treat it as gone
        return null
      }
    })

    return files
      .filter((file): file is EmlFile => file !== null)
      .sort((a, b) => b.mtimeMs - a.mtimeMs)
  }

  /**
   * Remove an email's .eml file and attachment directory, if they exist
   */
  private async removeEmailFiles(
    id: string,
    host?: string,
    mailDirOverride?: string
  ): Promise<void> {
    const mailDir = mailDirOverride ?? this.mailDirectoryForHost(host)
    try {
      await rm(join(mailDir, `${id}.eml`), { force: true })
    } catch (err) {
      this.logger.error('Error deleting email file:', err)
    }

    try {
      await rm(getAttachmentDir(mailDir, id), { recursive: true, force: true })
    } catch {
      // Directory may not exist
    }
  }
}

/**
 * Create an SMTP server instance
 */
export function createSMTPServer(options: SMTPServerOptions): SMTPServer {
  return new SMTPServer(options)
}
