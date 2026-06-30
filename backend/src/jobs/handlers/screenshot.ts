import { dirname, join, resolve } from 'node:path'
import { config } from '../../config'
import { getDomain } from '../../domains/store'
import { captureScreenshot, screenshotAvailable } from '../../sources/screenshot'
import { listSubdomains, updateScreenshot } from '../../subdomains/store'
import { mapLimit } from '../../util/async'
import type { JobContext } from '../worker'

const MAX_SHOTS = 80
const CONCURRENCY = 3

// Screenshots live next to the DB (the mounted /data volume in Docker).
export const SCREENSHOT_DIR = join(dirname(resolve(config.databasePath)), 'screenshots')

export function sanitizeHostForFile(host: string): string {
  return host.toLowerCase().replace(/[^a-z0-9._-]/g, '_').slice(0, 200)
}

export function screenshotPathFor(domainId: number, host: string): string {
  return join(SCREENSHOT_DIR, String(domainId), `${sanitizeHostForFile(host)}.png`)
}

// Screenshot the live web hosts of a domain (those that responded to the probe).
export async function screenshotHandler({ params, log }: JobContext) {
  const domainId = Number(params.domainId)
  const domain = getDomain(domainId)
  if (!domain) throw new Error(`domain ${domainId} not found`)

  if (!(await screenshotAvailable())) {
    return { available: false, note: 'chromium not installed in this image' }
  }

  // Only screenshot hosts that responded to HTTP/HTTPS during discovery.
  const live = listSubdomains(domainId)
    .filter((s) => s.httpStatus != null && s.scheme)
    .slice(0, MAX_SHOTS)

  if (live.length === 0) {
    return { available: true, captured: 0, note: 'no live web hosts to screenshot (run discovery first)' }
  }

  let captured = 0
  await mapLimit(
    live,
    CONCURRENCY,
    async (s) => {
      const url = `${s.scheme}://${s.host}`
      const out = screenshotPathFor(domainId, s.host)
      const ok = await captureScreenshot(url, out)
      if (ok) {
        updateScreenshot(domainId, s.host, out)
        captured++
      }
      return ok
    },
    false,
  )

  log.info({ domain: domain.host, captured, of: live.length }, 'screenshots captured')
  return { available: true, captured, attempted: live.length }
}
