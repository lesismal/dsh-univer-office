import type { IncomingMessage } from 'node:http'
import { describe, expect, it } from 'vitest'
import { isTrustedGatewayRequest } from '../../src/gateway-app/transport/request-fence.ts'

const PORT = 9080

function request(headers: Record<string, string>): IncomingMessage {
  return { headers } as unknown as IncomingMessage
}

describe('Gateway request fence', () => {
  it.each(['127.0.0.1:9080', 'localhost:9080', '[::1]:9080'])(
    'trusts Node callers addressing %s without an Origin',
    (host) => {
      expect(isTrustedGatewayRequest(request({ host }), PORT)).toBe(true)
    }
  )

  it('trusts the Gateway Viewer on its own origin', () => {
    const headers = {
      host: '127.0.0.1:9080',
      origin: 'http://127.0.0.1:9080',
      'sec-fetch-site': 'same-origin'
    }
    expect(isTrustedGatewayRequest(request(headers), PORT)).toBe(true)
  })

  it.each([
    ['a missing Host', {}],
    ['a rebinding Host', { host: 'attacker.example:9080' }],
    ['another loopback port', { host: '127.0.0.1:9081' }],
    ['a userinfo Host', { host: 'x@127.0.0.1:9080' }],
    ['a foreign Origin', { host: '127.0.0.1:9080', origin: 'https://attacker.example' }],
    ['a null Origin', { host: '127.0.0.1:9080', origin: 'null' }],
    ['another loopback Origin', { host: '127.0.0.1:9080', origin: 'http://127.0.0.1:3000' }],
    ['a cross-site fetch', { host: '127.0.0.1:9080', 'sec-fetch-site': 'cross-site' }],
    ['a same-site fetch', { host: '127.0.0.1:9080', 'sec-fetch-site': 'same-site' }]
  ])('refuses %s', (_label, headers: Record<string, string>) => {
    expect(isTrustedGatewayRequest(request(headers), PORT)).toBe(false)
  })
})
