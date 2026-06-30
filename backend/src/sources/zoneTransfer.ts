import { run, toolExists } from '../util/exec'
import { isValidDomain, isValidHostname } from '../util/validate'

export interface ZoneTransferResult {
  available: boolean // whether the `dig` tool exists
  vulnerable: boolean
  servers: { ns: string; records: number }[]
  sample?: string
}

// Attempt an AXFR (full DNS zone transfer) against each nameserver. A successful
// transfer is a real misconfiguration (leaks the whole zone). Passive-ish: it's
// a standard DNS query, no exploitation. Uses `dig` (graceful if absent).
export async function zoneTransfer(domain: string, nameservers: string[]): Promise<ZoneTransferResult> {
  if (!isValidDomain(domain)) throw new Error(`invalid domain: ${domain}`)
  if (!(await toolExists('dig'))) {
    return { available: false, vulnerable: false, servers: [] }
  }

  const servers: { ns: string; records: number }[] = []
  let sample: string | undefined

  for (const nsRaw of nameservers.slice(0, 8)) {
    const ns = nsRaw.replace(/\.$/, '')
    if (!isValidHostname(ns) && !isValidDomain(ns)) continue
    try {
      const { stdout } = await run(
        'dig',
        ['AXFR', domain, `@${ns}`, '+noidnout', '+time=8', '+tries=1'],
        { timeoutMs: 20_000 },
      )
      if (/;\s*Transfer failed|communications error|connection timed out|; Transfer/i.test(stdout) === false) {
        const m = stdout.match(/XFR size:\s*(\d+)/i)
        const records = m ? Number(m[1]) : stdout.split('\n').filter((l) => /\bIN\b/.test(l)).length
        if (records > 1) {
          servers.push({ ns, records })
          if (!sample) sample = stdout.split('\n').slice(0, 40).join('\n')
        }
      }
    } catch {
      // failed transfer = good (not vulnerable); ignore
    }
  }

  return { available: true, vulnerable: servers.length > 0, servers, sample }
}
