/** Status vocabulary shared by badges, headers and module placeholders. */
export type StatusKind =
  | 'ONLINE'
  | 'OFFLINE'
  | 'LIVE'
  | 'DEMO'
  | 'INITIALIZING'
  | 'NOT INITIALIZED'
  | 'ACTIVE'
  | 'INACTIVE'
  | 'WARNING'
  | 'CRITICAL'
  | 'FOUNDATION ONLINE'
  | 'BACKEND OFFLINE'
  | 'FOUNDATION CREATED'
  | 'FOUNDATION READY'
  | 'IN DEVELOPMENT'
  | 'OPERATIONAL'
  | 'IMPLEMENTED'
  | 'ARCHITECTURE DEFINED';

/** How a status reads semantically, independent of its label. */
export type StatusTone = 'success' | 'warning' | 'danger' | 'info' | 'neutral';

/** Implementation state of a module or architecture layer. */
export type ModuleStatus =
  | 'NOT INITIALIZED'
  | 'FOUNDATION CREATED'
  | 'FOUNDATION READY'
  | 'IN DEVELOPMENT'
  | 'OPERATIONAL'
  | 'IMPLEMENTED';

/** Result of the request lifecycle for any backend-backed view. */
export type RequestState = 'loading' | 'ready' | 'error';
