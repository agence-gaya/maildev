import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Command } from 'commander'
import { configureOptions } from '../../options.js'
import { loadConfig } from '../../config/loader.js'
import { resolveConfig } from '../../config/merge.js'
import type { CLIOptions } from '../../config/types.js'

// Mock the loader module to avoid file system access
vi.mock('../../config/loader.js', () => ({
  loadConfig: vi.fn().mockResolvedValue({ config: {}, filePath: null }),
}))

describe('resolveConfig', () => {
  const originalEnv = process.env

  beforeEach(() => {
    process.env = { ...originalEnv }
    // Clear any MAILDEV_ env vars
    Object.keys(process.env).forEach((key) => {
      if (key.startsWith('MAILDEV_')) {
        delete process.env[key]
      }
    })
  })

  afterEach(() => {
    process.env = originalEnv
    vi.clearAllMocks()
  })

  it('should return default config when no options provided', async () => {
    const { config } = await resolveConfig({})

    expect(config.smtp).toBe(1025)
    expect(config.web).toBe(1080)
    expect(config.ip).toBe('::')
    expect(config.webIp).toBe('0.0.0.0')
    expect(config.basePathname).toBe('/')
    expect(config.verbose).toBe(false)
    expect(config.mcp).toBe(false)
    expect(config.virtualHostPath).toBeUndefined()
  })

  it('should apply CLI options over defaults', async () => {
    const { config } = await resolveConfig({
      smtp: '2025',
      web: '3080',
      verbose: true,
    })

    expect(config.smtp).toBe(2025)
    expect(config.web).toBe(3080)
    expect(config.verbose).toBe(true)
  })

  it('should apply environment variables over defaults', async () => {
    process.env.MAILDEV_SMTP_PORT = '4025'
    process.env.MAILDEV_WEB_PORT = '5080'

    const { config } = await resolveConfig({})

    expect(config.smtp).toBe(4025)
    expect(config.web).toBe(5080)
  })

  it('should prioritize CLI options over environment variables', async () => {
    process.env.MAILDEV_SMTP_PORT = '4025'

    const { config } = await resolveConfig({
      smtp: '5025',
    })

    expect(config.smtp).toBe(5025)
  })

  it('should parse string port options as numbers', async () => {
    const { config } = await resolveConfig({
      smtp: '9025',
      web: '9080',
      outgoingPort: '587',
    })

    expect(config.smtp).toBe(9025)
    expect(typeof config.smtp).toBe('number')
    expect(config.web).toBe(9080)
    expect(typeof config.web).toBe('number')
    expect(config.outgoingPort).toBe(587)
    expect(typeof config.outgoingPort).toBe('number')
  })

  it('should handle string options correctly', async () => {
    const { config } = await resolveConfig({
      ip: '127.0.0.1',
      webIp: '192.168.1.1',
      basePathname: '/mail/',
      incomingUser: 'smtp_user',
      incomingPass: 'smtp_pass',
    })

    expect(config.ip).toBe('127.0.0.1')
    expect(config.webIp).toBe('192.168.1.1')
    expect(config.basePathname).toBe('/mail/')
    expect(config.incomingUser).toBe('smtp_user')
    expect(config.incomingPass).toBe('smtp_pass')
  })

  it('should handle boolean options correctly', async () => {
    const { config } = await resolveConfig({
      verbose: true,
      silent: false,
      mcp: true,
      disableWeb: true,
    })

    expect(config.verbose).toBe(true)
    expect(config.silent).toBe(false)
    expect(config.mcp).toBe(true)
    expect(config.disableWeb).toBe(true)
  })

  it('should parse virtual-host-path as a boolean CLI option and override the environment', async () => {
    process.env.MAILDEV_VIRTUAL_HOST_PATH = 'false'
    const program = new Command()
    configureOptions(program)
    program
      .exitOverride()
      .parse(['--virtual-host-path', '--base-pathname', '/maildev'], { from: 'user' })

    expect(program.opts<CLIOptions>().virtualHost).toBeUndefined()
    const { config } = await resolveConfig(program.opts<CLIOptions>())

    expect(config.virtualHost).toBe(false)
    expect(config.virtualHostPath).toBe(true)
    expect(config.basePathname).toBe('/maildev')
  })

  it('should preserve virtualHostPath from the environment when the CLI flag is absent', async () => {
    process.env.MAILDEV_VIRTUAL_HOST_PATH = 'true'
    const program = new Command()
    configureOptions(program)
    program.parse([], { from: 'user' })

    expect(program.opts<CLIOptions>().virtualHostPath).toBeUndefined()
    const { config } = await resolveConfig(program.opts<CLIOptions>())

    expect(config.virtualHostPath).toBe(true)
  })

  it('should load virtualHostPath from the config file when no overrides are provided', async () => {
    vi.mocked(loadConfig).mockResolvedValueOnce({
      config: { virtualHostPath: true },
      filePath: '/config/maildev.json',
    })

    const { config } = await resolveConfig({})

    expect(config.virtualHostPath).toBe(true)
  })

  it('should prioritize virtualHostPath from the environment over the config file', async () => {
    vi.mocked(loadConfig).mockResolvedValueOnce({
      config: { virtualHostPath: true },
      filePath: '/config/maildev.json',
    })
    process.env.MAILDEV_VIRTUAL_HOST_PATH = 'false'

    const { config } = await resolveConfig({})

    expect(config.virtualHostPath).toBe(false)
  })

  it('should preserve an explicit false CLI value over virtualHostPath from other sources', async () => {
    vi.mocked(loadConfig).mockResolvedValueOnce({
      config: { virtualHostPath: true },
      filePath: '/config/maildev.json',
    })
    process.env.MAILDEV_VIRTUAL_HOST_PATH = 'true'

    const { config } = await resolveConfig({ virtualHostPath: false })

    expect(config.virtualHostPath).toBe(false)
  })

  it('should handle auto-relay as boolean', async () => {
    const { config } = await resolveConfig({
      autoRelay: true,
    })

    expect(config.autoRelay).toBe(true)
  })

  it('should handle auto-relay as email string', async () => {
    const { config } = await resolveConfig({
      autoRelay: 'test@example.com',
    })

    expect(config.autoRelay).toBe('test@example.com')
  })

  it('should parse hideExtensions as array', async () => {
    const { config } = await resolveConfig({
      hideExtensions: 'STARTTLS,PIPELINING',
    })

    expect(config.hideExtensions).toEqual(['STARTTLS', 'PIPELINING'])
  })

  it('should handle hideExtensions with spaces', async () => {
    const { config } = await resolveConfig({
      hideExtensions: ' STARTTLS , PIPELINING , 8BITMIME ',
    })

    expect(config.hideExtensions).toEqual(['STARTTLS', 'PIPELINING', '8BITMIME'])
  })

  it('should convert hideExtensions to uppercase', async () => {
    const { config } = await resolveConfig({
      hideExtensions: 'starttls,pipelining',
    })

    expect(config.hideExtensions).toEqual(['STARTTLS', 'PIPELINING'])
  })

  it('should handle outgoing relay options', async () => {
    const { config } = await resolveConfig({
      outgoingHost: 'smtp.example.com',
      outgoingPort: '587',
      outgoingUser: 'relay_user',
      outgoingPass: 'relay_pass',
      outgoingSecure: true,
    })

    expect(config.outgoingHost).toBe('smtp.example.com')
    expect(config.outgoingPort).toBe(587)
    expect(config.outgoingUser).toBe('relay_user')
    expect(config.outgoingPass).toBe('relay_pass')
    expect(config.outgoingSecure).toBe(true)
  })

  it('should handle mail directory option', async () => {
    const { config } = await resolveConfig({
      mailDirectory: '/var/mail/test',
    })

    expect(config.mailDirectory).toBe('/var/mail/test')
  })

  it('should return null configFilePath when no config file found', async () => {
    const { configFilePath } = await resolveConfig({})

    expect(configFilePath).toBeNull()
  })

  it('should not override defined values when CLI options not provided', async () => {
    process.env.MAILDEV_SMTP_PORT = '4025'

    // Not providing smtp option at all (vs providing undefined)
    const { config } = await resolveConfig({})

    // Environment variable should apply
    expect(config.smtp).toBe(4025)
  })
})
