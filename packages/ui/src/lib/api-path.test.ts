import { afterEach, describe, expect, it, vi } from 'vitest'

describe('API URLs for path-based inboxes', () => {
  afterEach(() => {
    document.head.innerHTML = ''
    vi.unstubAllGlobals()
  })

  it('keeps REST requests and downloads under the page virtual-host prefix', async () => {
    document.head.innerHTML = '<base href="/maildev/alpha.test/">'
    vi.resetModules()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', fetchMock)
    const { api } = await import('./api')
    await api.emails.getSummaries({ search: 'hello world' })
    expect(fetchMock).toHaveBeenCalledWith(
      '/maildev/alpha.test/api/email/summary?search=hello+world'
    )
    expect(api.emails.downloadUrl('mail')).toBe('/maildev/alpha.test/api/email/mail/download')
    expect(api.emails.attachmentUrl('mail', 'image file.png')).toBe(
      '/maildev/alpha.test/api/email/mail/attachment/image%20file.png'
    )
  })
})
