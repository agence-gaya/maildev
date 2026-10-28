/**
 * Normalize an SMTP EHLO name or HTTP Host header for virtual-host routing
 */
export function normalizeVirtualHost(host?: string): string {
  const value = host?.trim()
  if (!value) {
    return 'default'
  }

  if (value.length > 300 || /[\\/%?#@\s]/.test(value)) {
    throw new Error(`Invalid virtual host: ${JSON.stringify(host)}`)
  }

  let hostname: string
  try {
    const url = new URL(`http://${value}`)
    if (url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
      throw new Error('Host must not contain a path or credentials')
    }
    hostname = url.hostname.toLowerCase().replace(/\.$/, '')
  } catch {
    throw new Error(`Invalid virtual host: ${JSON.stringify(host)}`)
  }

  const isIPv6 = /^\[[0-9a-f:.]+\]$/.test(hostname)
  const isHostname = hostname
    .split('.')
    .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))

  if (!hostname || (!isIPv6 && !isHostname)) {
    throw new Error(`Invalid virtual host: ${JSON.stringify(host)}`)
  }

  return hostname
}
