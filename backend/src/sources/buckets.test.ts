import { describe, expect, it } from 'vitest'
import { bucketCandidates } from './buckets'

describe('bucketCandidates', () => {
  it('derives scope-relevant names from the domain label', () => {
    const names = bucketCandidates('example.com')
    expect(names).toContain('example')
    expect(names).toContain('example-backup')
    expect(names).toContain('example-assets')
    // never the TLD or empty
    expect(names).not.toContain('com')
    expect(names.every((n) => n.length >= 3 && n.length <= 63)).toBe(true)
  })

  it('includes operator seeds and dedupes', () => {
    const names = bucketCandidates('acme.io', ['acme-corp'])
    expect(names).toContain('acme-corp')
    expect(names).toContain('acme-corp-backup')
    expect(new Set(names).size).toBe(names.length)
  })

  it('handles multi-label domains and is bounded', () => {
    const names = bucketCandidates('shop.example.co.uk')
    expect(names.length).toBeLessThanOrEqual(120)
    expect(names.length).toBeGreaterThan(0)
  })

  it('rejects names with illegal characters', () => {
    const names = bucketCandidates('foo_bar!.com', ['bad name'])
    expect(names.every((n) => /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(n))).toBe(true)
  })
})
