import type { RiskBand, RiskClassification } from '@/types';

/**
 * The locked risk classification. Bands are inclusive.
 * Classification is only applied to a real score produced by Layer 10.
 */
export const RISK_BANDS: readonly RiskBand[] = [
  { classification: 'SAFE', min: 0, max: 20 },
  { classification: 'LOW', min: 21, max: 40 },
  { classification: 'MODERATE', min: 41, max: 60 },
  { classification: 'HIGH', min: 61, max: 80 },
  { classification: 'CRITICAL', min: 81, max: 100 },
] as const;

export const RISK_SCORE_MIN = 0;
export const RISK_SCORE_MAX = 100;

/** Map a real score onto its band. Returns null for out-of-range input. */
export function classifyRiskScore(score: number): RiskClassification | null {
  if (!Number.isFinite(score) || score < RISK_SCORE_MIN || score > RISK_SCORE_MAX) {
    return null;
  }
  const rounded = Math.round(score);
  return RISK_BANDS.find((band) => rounded >= band.min && rounded <= band.max)
    ?.classification ?? null;
}
