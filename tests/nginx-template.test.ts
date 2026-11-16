import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// auth/check decides WHICH service a request is authorized against from
// X-Forwarded-Host. nginx passes client request headers into the auth_request
// subrequest, so unless every /sso-auth location overwrites that header with
// the real $host, the client picks the host the access map is checked against
// (fatal while the shared legacy X-Internal-Secret is still accepted).
const dir = join(__dirname, '..', 'nginx', 'conf.d')

function ssoAuthBlocks(text: string): string[] {
  const out: string[] = []
  const re = /location\s*=\s*\/sso-auth\s*\{([^}]*)\}/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text))) out.push(m[1])
  return out
}

describe('nginx /sso-auth templates', () => {
  const files = readdirSync(dir).filter((f) => f.endsWith('.conf'))
  const withAuth = files.filter((f) => ssoAuthBlocks(readFileSync(join(dir, f), 'utf8')).length > 0)

  it('at least one template defines /sso-auth (positive control)', () => {
    expect(withAuth.length).toBeGreaterThan(0)
  })

  it.each(withAuth)('%s pins X-Forwarded-Host to $host in /sso-auth', (f) => {
    for (const block of ssoAuthBlocks(readFileSync(join(dir, f), 'utf8'))) {
      expect(block).toMatch(/proxy_set_header\s+X-Forwarded-Host\s+\$host\s*;/)
    }
  })
})
