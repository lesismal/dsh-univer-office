import type { IncomingMessage } from 'node:http'

const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', 'localhost', '[::1]'])

/**
 * Browser fence for the loopback Gateway. The Gateway has no credentials of its own: its trusted
 * callers are the DSH Host, its Workers, and the Host's same-origin Viewer proxy, none of which
 * send a foreign `Origin`. Rejecting every cross-origin browser request and every non-loopback
 * `Host` header keeps arbitrary web pages (directly or through DNS rebinding) from reading or
 * mutating `.univer` files, while the Gateway's own Viewer origin keeps working.
 */
export function isTrustedGatewayRequest(req: IncomingMessage, port: number): boolean {
  const host = singleHeader(req.headers.host)
  if (host === undefined || !isLoopbackAuthority(host, port)) return false

  const fetchSite = singleHeader(req.headers['sec-fetch-site'])
  if (fetchSite !== undefined && fetchSite !== 'same-origin' && fetchSite !== 'none') return false

  const origin = singleHeader(req.headers.origin)
  if (origin === undefined) return true
  let parsed: URL
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  return (
    parsed.protocol === 'http:' &&
    parsed.origin === origin &&
    isLoopbackAuthority(parsed.host, port)
  )
}

function isLoopbackAuthority(authority: string, port: number): boolean {
  let parsed: URL
  try {
    parsed = new URL(`http://${authority}`)
  } catch {
    return false
  }
  return (
    parsed.host === authority.toLowerCase() &&
    LOOPBACK_HOSTNAMES.has(parsed.hostname) &&
    parsed.port === String(port)
  )
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined
  return Array.isArray(value) ? value.join(',') : value
}
