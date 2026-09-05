/**
 * Service layer.
 *
 * Implemented: healthService, systemStatusService.
 *
 * Reserved for later sections and deliberately not implemented yet:
 * packetService, sessionService, saService, baselineService, driftService,
 * anomalyService, vulnerabilityService, riskService, reportService.
 */

export { healthService } from './healthService';
export { systemStatusService } from './systemStatusService';
export { ApiError, NetworkError, eventStreamUrl, requestJson } from './httpClient';
