/**
 * Client service for Layer 05 — Security Assessment & Risk Engine.
 */

import { requestJson } from './httpClient';
import type { RiskAssessmentReport, RiskScoreSummary, SecurityFinding } from '@/types';

export const securityAssessmentService = {
  /** Fetch the comprehensive security posture assessment report */
  getAssessment(signal?: AbortSignal): Promise<RiskAssessmentReport> {
    return requestJson<RiskAssessmentReport>('/api/security-assessment', signal);
  },

  /** Query security findings with optional severity and category filters */
  getFindings(severity?: string, category?: string, signal?: AbortSignal): Promise<SecurityFinding[]> {
    const params = new URLSearchParams();
    if (severity && severity !== 'ALL') params.set('severity', severity);
    if (category && category !== 'ALL') params.set('category', category);
    const qs = params.toString();
    return requestJson<SecurityFinding[]>(`/api/security-assessment/findings${qs ? `?${qs}` : ''}`, signal);
  },

  /** Fetch quick risk score summary */
  getRiskScore(signal?: AbortSignal): Promise<RiskScoreSummary> {
    return requestJson<RiskScoreSummary>('/api/security-assessment/risk-score', signal);
  },
};
