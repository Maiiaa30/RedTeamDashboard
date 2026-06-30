import { getScorer } from '../scoring'
import { addFinding, type NewFinding } from './store'

// Score a finding with the active scorer, then persist it. The scorer's
// human-readable reasons are stored on the finding data (_scoreReasons) so the
// UI can explain why a finding scored the way it did.
export async function addScoredFinding(f: Omit<NewFinding, 'score'>): Promise<number> {
  const { score, tags, reasons } = await getScorer().score({ type: f.type, data: f.data })
  const data =
    reasons && reasons.length && f.data && typeof f.data === 'object' && !Array.isArray(f.data)
      ? { ...(f.data as Record<string, unknown>), _scoreReasons: reasons }
      : f.data
  return addFinding({
    ...f,
    data,
    score,
    tags: [...new Set([...(f.tags ?? []), ...tags])],
  })
}
