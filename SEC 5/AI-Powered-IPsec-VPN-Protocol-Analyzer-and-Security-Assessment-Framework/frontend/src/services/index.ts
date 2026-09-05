/**
 * Service layer.
 *
 * Implemented: healthService, systemStatusService, realtimeService, packetService.
 *
 * Reserved for later sections and deliberately not implemented yet:
 * packetService, sessionService, saService, baselineService, driftService,
 * anomalyService, vulnerabilityService, riskService, reportService.
 */

export { healthService } from './healthService';
export { systemStatusService } from './systemStatusService';
export { RealtimeService, parseRealtimeMessage, realtimeService } from './realtimeService';
export { ApiError, NetworkError, eventStreamUrl, requestJson } from './httpClient';
export { packetService, PacketServiceError } from './packetService';
