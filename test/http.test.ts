/**
 * Tests for the HTTP endpoint probe: status line, redirect chain (including
 * relative Location resolution), header selection and caps, bounded body reads,
 * certificate rejection and the per-phase timing marks. Every server here is a
 * local one — the suite never touches the network.
 *
 * ORACLE: test/oracle/anchors.py
 */

import { readFileSync } from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { createServer as createTcpServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Socket } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  checkHttp,
  DEFAULT_BODY_LIMIT_BYTES,
  DEFAULT_MAX_REDIRECTS,
  HEADER_VALUE_CAP,
  parseHttpUrl,
} from '../src/http.ts'

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

/** Body served by the truncation route; larger than any limit used below. */
const BIG_BODY_BYTES = 100_000
/** Body limit used by the truncation test. */
const SMALL_LIMIT_BYTES = 1_024
/** Content-Security-Policy value long enough to be cut at the header cap. */
const LONG_CSP_LENGTH = 500

describe('checkHttp', () => {
  let server: ReturnType<typeof createHttpServer>
  let tlsServer: ReturnType<typeof createHttpsServer>
  let base = ''
  let tlsBase = ''
  const sockets = new Set<Socket>()
  let closedPort = 0

  beforeAll(async () => {
    server = createHttpServer((request, response) => {
      const url = request.url ?? '/'
      if (url === '/ok') {
        response.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          server: 'netdoctor-test',
          'strict-transport-security': 'max-age=31536000',
          'x-frame-options': 'DENY',
          // Two cookies: the probe must count them and never echo their values.
          'set-cookie': ['session=secret-a; HttpOnly', 'theme=dark'],
        })
        response.end('hello http')
        return
      }
      if (url === '/big') {
        response.writeHead(200, { 'content-type': 'application/octet-stream' })
        response.end(Buffer.alloc(BIG_BODY_BYTES, 0x61))
        return
      }
      if (url === '/long-header') {
        response.writeHead(200, { 'content-type': 'text/plain', 'content-security-policy': 'a'.repeat(LONG_CSP_LENGTH) })
        response.end('ok')
        return
      }
      if (url === '/a') {
        response.writeHead(302, { location: '/b' })
        response.end()
        return
      }
      if (url === '/b') {
        response.writeHead(301, { location: 'c' })
        response.end()
        return
      }
      if (url === '/c') {
        response.writeHead(200, { 'content-type': 'text/plain' })
        response.end('arrived')
        return
      }
      if (url === '/dir/start') {
        response.writeHead(307, { location: '../up' })
        response.end()
        return
      }
      if (url === '/up') {
        response.writeHead(200, { 'content-type': 'text/plain' })
        response.end('up')
        return
      }
      if (url === '/loop') {
        response.writeHead(302, { location: '/loop' })
        response.end()
        return
      }
      if (url === '/noloc') {
        response.writeHead(302, { 'content-type': 'text/plain' })
        response.end('no location here')
        return
      }
      if (url === '/missing') {
        response.writeHead(404, { 'content-type': 'text/plain' })
        response.end('nope')
        return
      }
      if (url === '/hang') return // never answers: the timeout path
      if (url === '/down') {
        request.socket.destroy()
        return
      }
      response.writeHead(500, { 'content-type': 'text/plain' })
      response.end('unexpected route ' + url)
    })
    server.on('connection', (socket: Socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

    tlsServer = createHttpsServer(
      { key: readFileSync(join(fixtures, 'key.pem')), cert: readFileSync(join(fixtures, 'cert.pem')) },
      (_request, response) => {
        response.writeHead(200, { 'content-type': 'text/plain' })
        response.end('secure hello')
      },
    )
    await new Promise<void>((resolve) => tlsServer.listen(0, '127.0.0.1', resolve))
    tlsBase = `https://127.0.0.1:${(tlsServer.address() as AddressInfo).port}`

    const probe = createTcpServer()
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
    closedPort = (probe.address() as AddressInfo).port
    await new Promise<void>((resolve) => probe.close(() => resolve()))
  })

  afterAll(async () => {
    for (const socket of sockets) socket.destroy()
    await new Promise<void>((resolve) => server.close(() => resolve()))
    await new Promise<void>((resolve) => tlsServer.close(() => resolve()))
  })

  it('reports the status line, selected headers and the body read', async () => {
    const result = await checkHttp(`${base}/ok`, { timeoutMs: 5_000 })
    expect(result.reachable).toBe(true)
    expect(result.status).toBe(200)
    expect(result.statusText).toBe('OK')
    expect(result.httpVersion).toBe('1.1')
    expect(result.finalUrl).toBe(`${base}/ok`)
    expect(result.redirected).toBe(0)
    expect(result.headers['content-type']).toBe('text/plain; charset=utf-8')
    expect(result.headers['strict-transport-security']).toBe('max-age=31536000')
    expect(result.headers['x-frame-options']).toBe('DENY')
    expect(result.bodyBytes).toBe('hello http'.length)
    expect(result.bodyTruncated).toBe(false)
    // cookie values are counted, never echoed
    expect(result.setCookieCount).toBe(2)
    expect(JSON.stringify(result)).not.toContain('secret-a')
  })

  it('omits headers it was not asked to report (no wire dump)', async () => {
    const result = await checkHttp(`${base}/ok`, { timeoutMs: 5_000 })
    // the test server always sends Connection/keep-alive style framing headers
    expect(result.headers.connection).toBeUndefined()
    expect(Object.keys(result.headers)).not.toContain('set-cookie')
  })

  it('records timing marks in order, with no DNS mark for an IP literal', async () => {
    const result = await checkHttp(`${base}/ok`, { timeoutMs: 5_000 })
    const { connectMs, ttfbMs, totalMs, dnsMs } = result.timing
    // 127.0.0.1 needs no name resolution, so there is no DNS phase to report
    expect(dnsMs).toBeUndefined()
    expect(connectMs).toBeTypeOf('number')
    expect(ttfbMs).toBeTypeOf('number')
    expect(connectMs as number).toBeGreaterThanOrEqual(0)
    expect(ttfbMs as number).toBeGreaterThanOrEqual(connectMs as number)
    expect(totalMs).toBeGreaterThanOrEqual(ttfbMs as number)
  })

  it('follows a redirect chain and resolves a relative Location against the current URL', async () => {
    const result = await checkHttp(`${base}/a`, { timeoutMs: 5_000 })
    expect(result.status).toBe(200)
    expect(result.redirected).toBe(2)
    expect(result.redirectChain.map((hop) => hop.status)).toEqual([302, 301])
    expect(result.redirectChain[0]?.location).toBe(`${base}/b`)
    // "c" is resolved against /b, giving /c — not /a/c and not a bare "c"
    expect(result.redirectChain[1]?.location).toBe(`${base}/c`)
    expect(result.finalUrl).toBe(`${base}/c`)
    expect(result.bodyBytes).toBe('arrived'.length)
  })

  it('resolves a parent-relative Location (../) the way RFC 3986 does', async () => {
    const result = await checkHttp(`${base}/dir/start`, { timeoutMs: 5_000 })
    expect(result.finalUrl).toBe(`${base}/up`)
    expect(result.redirected).toBe(1)
  })

  it('stops at the redirect limit and says so instead of looping', async () => {
    const result = await checkHttp(`${base}/loop`, { timeoutMs: 5_000, maxRedirects: 3 })
    expect(result.redirected).toBe(3)
    expect(result.status).toBe(302)
    expect(result.reachable).toBe(true)
    expect(result.note).toContain('maxRedirects')
  })

  it('reports a redirect status without a Location header as the final answer', async () => {
    const result = await checkHttp(`${base}/noloc`, { timeoutMs: 5_000 })
    expect(result.status).toBe(302)
    expect(result.redirected).toBe(0)
    expect(result.bodyBytes).toBe('no location here'.length)
  })

  it('keeps 4xx responses as reachable results rather than errors', async () => {
    const result = await checkHttp(`${base}/missing`, { timeoutMs: 5_000 })
    expect(result.reachable).toBe(true)
    expect(result.status).toBe(404)
    expect(result.error).toBeUndefined()
    expect(result.bodyBytes).toBe('nope'.length)
  })

  it('reads at most bodyLimitBytes and marks the body truncated', async () => {
    const result = await checkHttp(`${base}/big`, { timeoutMs: 5_000, bodyLimitBytes: SMALL_LIMIT_BYTES })
    expect(result.bodyTruncated).toBe(true)
    expect(result.bodyBytes).toBeGreaterThanOrEqual(SMALL_LIMIT_BYTES)
    expect(result.bodyBytes).toBeLessThan(BIG_BODY_BYTES)
  })

  it('cuts a single oversized header value at the cap and counts the cut', async () => {
    const result = await checkHttp(`${base}/long-header`, { timeoutMs: 5_000 })
    expect(result.headers['content-security-policy']).toHaveLength(HEADER_VALUE_CAP)
    expect(result.headersTruncated).toBe(1)
  })

  it('sends HEAD without reading a body', async () => {
    const result = await checkHttp(`${base}/ok`, { timeoutMs: 5_000, method: 'HEAD' })
    expect(result.status).toBe(200)
    expect(result.method).toBe('HEAD')
    expect(result.bodyBytes).toBe(0)
    expect(result.bodyTruncated).toBe(false)
  })

  it('rejects a self-signed certificate by default and proceeds with insecure: true', async () => {
    const rejected = await checkHttp(`${tlsBase}/`, { timeoutMs: 5_000 })
    expect(rejected.reachable).toBe(false)
    expect(rejected.error).toContain('certificate rejected')

    const accepted = await checkHttp(`${tlsBase}/`, { timeoutMs: 5_000, insecure: true })
    expect(accepted.reachable).toBe(true)
    expect(accepted.status).toBe(200)
    expect(accepted.timing.tlsMs).toBeTypeOf('number')
    expect(accepted.timing.tlsMs as number).toBeGreaterThanOrEqual(accepted.timing.connectMs as number)
  })

  it('reports connection refused and host-lookup failures as unreachable', async () => {
    const refused = await checkHttp(`http://127.0.0.1:${closedPort}/`, { timeoutMs: 3_000 })
    expect(refused.reachable).toBe(false)
    expect(refused.status).toBe(0)
    expect(refused.error).toContain('refused')

    const noHost = await checkHttp('http://this-host-does-not-exist-zz.invalid/', { timeoutMs: 3_000 })
    expect(noHost.reachable).toBe(false)
    expect(noHost.error).toContain('lookup failed')
  })

  it('times out a server that never answers', async () => {
    const started = Date.now()
    const result = await checkHttp(`${base}/hang`, { timeoutMs: 200 })
    expect(result.reachable).toBe(false)
    expect(result.error).toContain('did not complete')
    expect(Date.now() - started).toBeLessThan(3_000)
  })

  it('reports a peer that resets the connection', async () => {
    const result = await checkHttp(`${base}/down`, { timeoutMs: 3_000 })
    expect(result.reachable).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('validates the URL and every numeric option', async () => {
    await expect(checkHttp('not-a-url')).rejects.toThrow()
    await expect(checkHttp('')).rejects.toThrow()
    await expect(checkHttp('ftp://example.com/')).rejects.toThrow(/scheme/)
    await expect(checkHttp('https://user:pass@example.com/')).rejects.toThrow(/credentials/)
    await expect(checkHttp(`${base}/ok`, { timeoutMs: 50 })).rejects.toThrow()
    await expect(checkHttp(`${base}/ok`, { timeoutMs: 60_001 })).rejects.toThrow()
    await expect(checkHttp(`${base}/ok`, { maxRedirects: 11 })).rejects.toThrow()
    await expect(checkHttp(`${base}/ok`, { maxRedirects: 1.5 })).rejects.toThrow()
    await expect(checkHttp(`${base}/ok`, { bodyLimitBytes: 0 })).rejects.toThrow()
    await expect(checkHttp(`${base}/ok`, { bodyLimitBytes: 2_000_000 })).rejects.toThrow()
    await expect(checkHttp(`${base}/ok`, { method: 'POST' as unknown as 'GET' })).rejects.toThrow()
  })
})

describe('parseHttpUrl', () => {
  it('keeps an explicit port and adds the scheme default when it is absent', () => {
    expect(parseHttpUrl('https://example.com/').port).toBe('')
    expect(parseHttpUrl('https://example.com/').protocol).toBe('https:')
    expect(parseHttpUrl('http://example.com:8080/x').port).toBe('8080')
  })

  it('trims surrounding whitespace', () => {
    expect(parseHttpUrl('  https://example.com/  ').toString()).toBe('https://example.com/')
  })

  it('uses the anchor defaults', () => {
    expect(DEFAULT_MAX_REDIRECTS).toBe(5)
    expect(DEFAULT_BODY_LIMIT_BYTES).toBe(8_192)
    expect(HEADER_VALUE_CAP).toBe(200)
  })
})
