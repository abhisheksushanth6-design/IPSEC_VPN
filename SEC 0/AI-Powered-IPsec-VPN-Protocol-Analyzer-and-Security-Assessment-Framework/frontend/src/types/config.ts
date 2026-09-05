/** Client-side configuration resolved from Vite environment variables. */

export type ApplicationMode = 'DEMO' | 'DEVELOPMENT' | 'PRODUCTION';

export interface ApplicationConfiguration {
  apiBaseUrl: string;
  wsBaseUrl: string;
  eventsPath: string;
}
