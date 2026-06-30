import { getDomain } from '../../domains/store'
import { addScoredFinding } from '../../findings/score'
import { addFinding } from '../../findings/store'
import { crtShSubdomains } from '../../sources/crtsh'
import { resolveDns } from '../../sources/dns'
import { internetDbLookup } from '../../sources/internetdb'
import { whoisDomain } from '../../sources/whois'
import { zoneTransfer } from '../../sources/zoneTransfer'
import { isValidIp } from '../../util/validate'
import type { JobContext } from '../worker'

// Phase 4: OSINT / info center. One screen's worth of passive intel about a
// target, aggregated from several sources. All passive.
export async function osintHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)
  const host = domain.host

  const result: Record<string, unknown> = { domain: host }

  // DNS
  try {
    result.dns = await resolveDns(host)
  } catch (err) {
    result.dns = { error: err instanceof Error ? err.message : String(err) }
    log.warn({ host, err }, 'osint dns failed')
  }

  // WHOIS
  try {
    result.whois = await whoisDomain(host)
  } catch (err) {
    result.whois = { error: err instanceof Error ? err.message : String(err) }
    log.warn({ host, err }, 'osint whois failed')
  }

  // crt.sh count (subdomain breadth)
  try {
    const crt = await crtShSubdomains(host)
    result.crtsh = { count: crt.length, sample: crt.slice(0, 50) }
  } catch (err) {
    result.crtsh = { error: err instanceof Error ? err.message : String(err) }
  }

  // DNS zone transfer (AXFR) against the zone's nameservers.
  try {
    const dns = result.dns as { ns?: string[] } | undefined
    const ns = dns?.ns ?? []
    if (ns.length) {
      const zt = await zoneTransfer(host, ns)
      result.zoneTransfer = zt
      if (zt.vulnerable) {
        addFinding({
          domainId,
          type: 'osint',
          data: { kind: 'zone_transfer', domain: host, servers: zt.servers, sample: zt.sample },
          tags: ['zone-transfer', 'misconfig', 'critical'],
          score: 90,
        })
      }
    }
  } catch (err) {
    result.zoneTransfer = { error: err instanceof Error ? err.message : String(err) }
  }

  // InternetDB for the apex's first IP
  try {
    const dns = result.dns as { a?: string[] } | undefined
    const ip = dns?.a?.[0]
    if (ip && isValidIp(ip)) {
      result.internetdb = await internetDbLookup(ip)
    }
  } catch (err) {
    result.internetdb = { error: err instanceof Error ? err.message : String(err) }
  }

  await addScoredFinding({ domainId, type: 'osint', data: result, tags: ['osint'] })

  return result
}
