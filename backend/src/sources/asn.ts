import { Socket } from 'node:net'
import { isValidIp } from '../util/validate'

// ASN / BGP enrichment via Team Cymru's bulk WHOIS interface (whois.cymru.com,
// TCP 43). Keyless, no rate limit, one round-trip for many IPs — turns raw
// exposed IPs into org-attributed intel (which ASN/prefix owns them, so shared-
// hosting neighbours and org-owned ranges become visible). Passive.

const TIMEOUT_MS = 12_000
const MAX_RESPONSE_BYTES = 512 * 1024

export interface AsnInfo {
  ip: string
  asn: string | null
  prefix: string | null
  country: string | null
  registry: string | null
  asName: string | null
}

// One bulk query: "begin/verbose/<ips>/end" returns a header line then one
// pipe-delimited row per IP: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
function cymruBulk(ips: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = new Socket()
    let data = ''
    let bytes = 0
    let settled = false

    socket.setTimeout(TIMEOUT_MS)
    const hardDeadline = setTimeout(() => done(new Error('cymru overall timeout')), TIMEOUT_MS)
    hardDeadline.unref()

    function done(err?: Error) {
      if (settled) return
      settled = true
      clearTimeout(hardDeadline)
      socket.destroy()
      if (err) reject(err)
      else resolve(data)
    }

    socket.on('timeout', () => done(new Error('cymru timeout')))
    socket.on('error', (err) => done(err))
    socket.on('data', (chunk) => {
      bytes += chunk.length
      if (bytes > MAX_RESPONSE_BYTES) return done()
      data += chunk.toString('utf8')
    })
    socket.on('close', () => done())
    socket.connect(43, 'whois.cymru.com', () => {
      socket.write(`begin\nverbose\n${ips.join('\n')}\nend\n`)
    })
  })
}

function clean(s: string | undefined): string | null {
  const v = (s ?? '').trim()
  return v && v !== 'NA' ? v : null
}

/** Look up ASN/prefix/org for many IPs at once. Best-effort: returns an empty map on failure. */
export async function asnLookup(ipsIn: string[]): Promise<Map<string, AsnInfo>> {
  const ips = [...new Set(ipsIn.filter(isValidIp))].slice(0, 200)
  const out = new Map<string, AsnInfo>()
  if (!ips.length) return out
  let raw: string
  try {
    raw = await cymruBulk(ips)
  } catch {
    return out
  }
  for (const line of raw.split('\n')) {
    const t = line.trim()
    if (!t || /^AS\s*\|/i.test(t) || /bulk mode/i.test(t)) continue // skip header/banner
    const parts = t.split('|').map((p) => p.trim())
    if (parts.length < 7) continue
    const [asn, ip, prefix, cc, registry, , asName] = parts
    if (!isValidIp(ip)) continue
    out.set(ip, {
      ip,
      asn: clean(asn),
      prefix: clean(prefix),
      country: clean(cc),
      registry: clean(registry),
      asName: clean(asName),
    })
  }
  return out
}
