/**
 * Service layer.
 *
 * Implemented: healthService, systemStatusService, realtimeService, packetService,
 * sessionService, saService, featureService, baselineService.
 *
 * Reserved for later sections and deliberately not implemented yet:
 * driftService, anomalyService, vulnerabilityService, riskService, reportService.
 */

export { healthService } from './healthService';
export { systemStatusService } from './systemStatusService';
export { RealtimeService, parseRealtimeMessage, realtimeService } from './realtimeService';
export { ApiError, NetworkError, eventStreamUrl, requestJson } from './httpClient';
export { packetService, PacketServiceError } from './packetService';
export { sessionService } from './sessionService';
export { saService } from './saService';
export { featureService } from './featureService';
export { baselineService } from './baselineService';
export { driftService } from './driftService';
export { aiAnomalyService } from './aiAnomalyService';
export { vulnerabilityService } from './vulnerabilityService';
