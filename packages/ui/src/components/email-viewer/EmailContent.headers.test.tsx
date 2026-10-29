import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import type { Email } from '@maildev/core'
import { EmailContent } from './EmailContent'

vi.mock('../../hooks/useEmails', () => ({
  useEmailHtml: () => ({ data: undefined }),
  useEmailSource: () => ({ data: undefined }),
}))

const baseEmail: Email = {
  id: 'abc123',
  time: new Date(),
  read: true,
  subject: 'Message subject',
  source: '/tmp/abc123.eml',
  size: 1024,
  sizeHuman: '1 KB',
  from: [{ address: 'header-sender@example.com' }],
  to: [{ address: 'header-recipient@example.com' }],
  headers: {
    'X-Zebra': 'last',
    From: 'smtp-sender@example.com',
    To: 'smtp-recipient@example.com',
    Date: 'Thu, 29 Oct 2026 02:09:00 +0000',
    'Content-Type': 'text/plain; charset=utf-8',
    Subject: 'Message subject',
    'X-Alpha': ['first', 'second'],
    'X-Trace': 'first trace',
    'x-trace': 'second trace',
  },
  headerLines: [
    { name: 'From', value: 'smtp-sender@example.com' },
    { name: 'To', value: 'smtp-recipient@example.com' },
    { name: 'Date', value: 'Thu, 29 Oct 2026 02:09:00 +0000' },
    { name: 'Content-Type', value: 'text/plain; charset=utf-8' },
    { name: 'X-Trace', value: 'first trace' },
    { name: 'X-Alpha', value: 'first' },
    { name: 'X-Trace', value: 'second trace' },
    { name: 'X-Alpha', value: 'second' },
    { name: 'Subject', value: 'Message subject' },
    { name: 'X-Zebra', value: 'last' },
  ],
  attachments: [],
  envelope: {
    from: { address: 'smtp-sender@example.com', args: false },
    to: [
      { address: 'smtp-recipient@example.com', args: false },
      { address: 'hidden-recipient@example.com', args: { NOTIFY: ['SUCCESS'] } },
    ],
    host: 'test1.maildev.local',
    remoteAddress: '172.17.15.1',
  },
}

function renderHeaders(email: Email = baseEmail) {
  render(<EmailContent email={email} />)
  fireEvent.click(screen.getByRole('button', { name: 'Headers' }))
}

describe('EmailContent headers tab', () => {
  it('shows SMTP envelope data separately from the message headers in source order', () => {
    renderHeaders()

    const envelope = within(screen.getByRole('table', { name: 'SMTP envelope' }))
    expect(envelope.getByText('smtp-sender@example.com (args: false)')).toBeTruthy()
    expect(envelope.getByText('smtp-recipient@example.com (args: false)')).toBeTruthy()
    expect(
      envelope.getByText('hidden-recipient@example.com (args: {"NOTIFY":["SUCCESS"]})')
    ).toBeTruthy()
    expect(envelope.getByText('EHLO')).toBeTruthy()
    expect(envelope.getByText('test1.maildev.local')).toBeTruthy()
    expect(envelope.getByText('172.17.15.1')).toBeTruthy()

    const headers = within(screen.getByRole('table', { name: 'Message headers' }))
    expect(headers.queryByText('header-sender@example.com')).toBeNull()
    expect(headers.getByText('smtp-sender@example.com')).toBeTruthy()
    expect(headers.getByText('smtp-recipient@example.com')).toBeTruthy()
    expect(headers.getByText('Thu, 29 Oct 2026 02:09:00 +0000')).toBeTruthy()
    expect(headers.getByText('text/plain; charset=utf-8')).toBeTruthy()
    expect(headers.getByText('Message subject')).toBeTruthy()
    expect(headers.getByText('first')).toBeTruthy()
    expect(headers.getByText('second')).toBeTruthy()
    expect(headers.getByText('first trace')).toBeTruthy()
    expect(headers.getByText('second trace')).toBeTruthy()
    expect(
      Array.from(
        screen.getByRole('table', { name: 'Message headers' }).querySelectorAll('tr td:first-child')
      ).map((cell) => cell.textContent)
    ).toEqual([
      'From',
      'To',
      'Date',
      'Content-Type',
      'X-Trace',
      'X-Alpha',
      'X-Trace',
      'X-Alpha',
      'Subject',
      'X-Zebra',
    ])
  })

  it('keeps the available object order for emails without ordered header lines', () => {
    const {
      headers: _headers,
      headerLines: _headerLines,
      ...emailWithoutOrderedHeaders
    } = baseEmail
    renderHeaders({
      ...emailWithoutOrderedHeaders,
      headers: { Zeta: 'last', Alpha: 'first' },
    })

    expect(
      Array.from(
        screen.getByRole('table', { name: 'Message headers' }).querySelectorAll('tr td:first-child')
      ).map((cell) => cell.textContent)
    ).toEqual(['Zeta', 'Alpha'])
  })

  it('keeps the SMTP envelope visible when message headers are absent', () => {
    renderHeaders({ ...baseEmail, headers: {}, headerLines: [] })

    expect(screen.getByText('No message headers available')).toBeTruthy()
    expect(screen.getByRole('table', { name: 'SMTP envelope' }).textContent).toContain(
      '172.17.15.1'
    )
  })

  it('shows an empty SMTP sender and handles an empty recipient list', () => {
    renderHeaders({
      ...baseEmail,
      envelope: { from: { address: '' }, to: [] },
    })

    const envelope = screen.getByRole('table', { name: 'SMTP envelope' })
    expect(envelope.textContent).toContain('<>')
    expect(envelope.textContent).toContain('<none>')
    expect(envelope.textContent).not.toContain('EHLO')
    expect(envelope.textContent).not.toContain('Remote address')
  })

  it('renders envelope values as text rather than interpreting them as HTML', () => {
    const markup = '<img src=x onerror=alert(1)>'
    renderHeaders({
      ...baseEmail,
      envelope: { from: { address: markup }, to: [], remoteAddress: markup },
    })

    const envelope = screen.getByRole('table', { name: 'SMTP envelope' })
    expect(envelope.querySelector('img')).toBeNull()
    expect(envelope.textContent).toContain(markup)
  })
})
