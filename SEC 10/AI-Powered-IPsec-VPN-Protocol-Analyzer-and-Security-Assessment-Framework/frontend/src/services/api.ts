/**
 * Compatibility surface for the Section 0 API module.
 *
 * New code should import from the named services in `@/services` instead.
 */

export { healthService } from './healthService';
export { systemStatusService } from './systemStatusService';
export { ApiError, NetworkError, eventStreamUrl } from './httpClient';
