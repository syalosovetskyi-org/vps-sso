import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { NextRequest } from 'next/server'

// Test-only placeholders, not real credentials.
const JWT = 'unit-test-jwt-key-0123456789abcdef'
const NGINX = 'unit-test-nginx-shared'
const HOST = 'reader.example.test'
const OTHER = 'admin.example.test'

async function loadRoute() {
  vi.resetModules()
  return import('../src/app/api/auth/check/route')
}

async function humanToken(email: string): Promise<string> {
  const { signToken } = await import('../src/lib/jwt')
  return signToken({ sub: 'user_1', email, name: 'U' })
}

function req(host: string, token: string): NextRequest {
  return new NextRequest('http://127.0.0.1:3000/api/auth/check', {
    headers: {
      'x-forwarded-host': host,
      'x-internal-secret': NGINX,
      cookie: `sso_token=${token}`,
    },
  })
}

beforeEach(() => {
  vi.stubEnv('JWT_SECRET', JWT)
  vi.stubEnv('INTERNAL_SECRET', NGINX)
  vi.stubEnv('SSO_INTERNAL_LEGACY', 'on')
  vi.stubEnv('SSO_INTERNAL_SECRETS', '')
  vi.stubEnv('SSO_ASSERT_KEYS', '')
  // No live config-store: without a token fetchAccessMapLive() never hits the network.
  vi.stubEnv('CONFIG_STORE_TOKEN', '')
  vi.stubEnv('ALLOWED_EMAILS', '')
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('auth/check access map', () => {
  it('positive control: the access map grants only the listed host', async () => {
    vi.stubEnv('SSO_ACCESS', JSON.stringify({ 'user@example.test': [HOST] }))
    const { GET } = await loadRoute()
    const token = await humanToken('user@example.test')
    expect((await GET(req(HOST, token))).status).toBe(200)
    expect((await GET(req(OTHER, token))).status).toBe(403)
  })

  it('fails CLOSED when no access map is available at all', async () => {
    // config-store unreachable AND no usable SSO_ACCESS snapshot AND no
    // explicit ALLOWED_EMAILS: an authenticated user must NOT get every host.
    vi.stubEnv('SSO_ACCESS', '')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { GET } = await loadRoute()
    const token = await humanToken('anyone@example.test')
    expect((await GET(req(OTHER, token))).status).toBe(403)
    expect(err).toHaveBeenCalled()
  })

  it('fails CLOSED when the SSO_ACCESS snapshot is malformed', async () => {
    vi.stubEnv('SSO_ACCESS', '{not-json')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const { GET } = await loadRoute()
    const token = await humanToken('anyone@example.test')
    expect((await GET(req(OTHER, token))).status).toBe(403)
  })

  it('an explicit ALLOWED_EMAILS fallback still works when set', async () => {
    vi.stubEnv('SSO_ACCESS', '')
    vi.stubEnv('ALLOWED_EMAILS', 'ok@example.test')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const { GET } = await loadRoute()
    expect((await GET(req(HOST, await humanToken('ok@example.test')))).status).toBe(200)
    expect((await GET(req(HOST, await humanToken('no@example.test')))).status).toBe(403)
  })
})
