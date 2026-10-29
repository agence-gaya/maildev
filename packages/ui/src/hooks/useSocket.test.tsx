import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { useSocket } from './useSocket'

const socketListeners = vi.hoisted(() => new Map<string, (...args: unknown[]) => void>())
const disconnect = vi.hoisted(() => vi.fn())
const socketOptions = vi.hoisted(() => vi.fn())

vi.mock('socket.io-client', () => ({
  io: (options: unknown) => {
    socketOptions(options)
    return {
      on: (event: string, listener: (...args: unknown[]) => void) => {
        socketListeners.set(event, listener)
      },
      disconnect,
    }
  },
}))

describe('useSocket relay notifications', () => {
  afterEach(() => {
    socketListeners.clear()
    disconnect.mockClear()
    socketOptions.mockClear()
    document.head.innerHTML = ''
  })

  it('invalidates the open message after another client relays it', () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidateQueries = vi.spyOn(queryClient, 'invalidateQueries')
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )
    const { unmount } = renderHook(() => useSocket(), { wrapper })

    socketListeners.get('relayMail')?.({ id: 'mail-123' })

    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['email', 'mail-123'] })
    unmount()
    queryClient.clear()
  })

  it('uses the shared transport and the virtual host injected for the page path', () => {
    document.head.innerHTML =
      '<base href="/maildev/alpha.test/">' +
      '<meta name="maildev-virtual-host" content="alpha.test">' +
      '<meta name="maildev-socket-path" content="/maildev/socket.io">'
    const queryClient = new QueryClient()
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )
    const { unmount } = renderHook(() => useSocket(), { wrapper })
    expect(socketOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        path: '/maildev/socket.io',
        auth: { virtualHost: 'alpha.test' },
      })
    )
    unmount()
    queryClient.clear()
  })
})
