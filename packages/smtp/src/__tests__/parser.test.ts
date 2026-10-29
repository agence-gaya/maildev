import { describe, it, expect } from 'vitest'
import { parseEmailBuffer } from '../parser.js'

describe('parseEmailBuffer attachment contentId', () => {
  it('stores the bare contentId stripped of the Content-ID angle brackets', async () => {
    const svg = Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg"><rect width="4" height="4"/></svg>'
    )
    const raw = [
      'From: sender@example.com',
      'To: recipient@example.com',
      'Subject: inline svg',
      'MIME-Version: 1.0',
      'Content-Type: multipart/related; boundary="b"',
      '',
      '--b',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<html><body><img src="cid:logo@maildev.test" alt="svg"></body></html>',
      '--b',
      'Content-Type: image/svg+xml',
      'Content-Disposition: inline',
      'Content-ID: <logo@maildev.test>',
      'Content-Transfer-Encoding: base64',
      '',
      svg.toString('base64'),
      '--b--',
      '',
    ].join('\r\n')

    const parsed = await parseEmailBuffer(raw)

    const attachments = parsed.attachments ?? []
    expect(attachments).toHaveLength(1)
    expect(attachments[0]!.contentId).toBe('logo@maildev.test')
  })

  it('keeps a bare contentId unchanged', async () => {
    const raw = [
      'From: sender@example.com',
      'To: recipient@example.com',
      'Subject: inline png',
      'MIME-Version: 1.0',
      'Content-Type: multipart/related; boundary="b"',
      '',
      '--b',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<html><body><img src="cid:logo" alt="png"></body></html>',
      '--b',
      'Content-Type: image/png',
      'Content-Disposition: inline',
      'Content-ID: logo',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('png').toString('base64'),
      '--b--',
      '',
    ].join('\r\n')

    const parsed = await parseEmailBuffer(raw)

    const attachments = parsed.attachments ?? []
    expect(attachments).toHaveLength(1)
    expect(attachments[0]!.contentId).toBe('logo')
  })
})

describe('parseEmailBuffer headers', () => {
  it('preserves structured, repeated, and folded message headers', async () => {
    const raw = [
      'From: sender@example.com',
      'To: recipient@example.com',
      'Date: Thu, 29 Oct 2026 02:09:00 +0000',
      'Content-Type: text/plain; charset=utf-8',
      'X-Trace: first: value',
      'X-Description: first line',
      '\tcontinued line',
      'X-Trace: repeated value',
      'x-trace: second value',
      '',
      'Body',
    ].join('\r\n')

    const parsed = await parseEmailBuffer(raw)

    expect(parsed.headers?.get('From')).toBe('sender@example.com')
    expect(parsed.headers?.get('To')).toBe('recipient@example.com')
    expect(parsed.headers?.get('Date')).toBe('Thu, 29 Oct 2026 02:09:00 +0000')
    expect(parsed.headers?.get('Content-Type')).toBe('text/plain; charset=utf-8')
    expect(parsed.headers?.get('X-Trace')).toEqual(['first: value', 'repeated value'])
    expect(parsed.headers?.get('x-trace')).toBe('second value')
    expect(parsed.headers?.get('X-Description')).toBe('first line continued line')
    expect(parsed.headerLines).toEqual([
      { name: 'From', value: 'sender@example.com' },
      { name: 'To', value: 'recipient@example.com' },
      { name: 'Date', value: 'Thu, 29 Oct 2026 02:09:00 +0000' },
      { name: 'Content-Type', value: 'text/plain; charset=utf-8' },
      { name: 'X-Trace', value: 'first: value' },
      { name: 'X-Description', value: 'first line continued line' },
      { name: 'X-Trace', value: 'repeated value' },
      { name: 'x-trace', value: 'second value' },
    ])
  })

  it('returns an empty map when a message has no headers', async () => {
    const parsed = await parseEmailBuffer('\r\nBody')

    expect(parsed.headers?.size).toBe(0)
    expect(parsed.headerLines).toEqual([])
  })
})
