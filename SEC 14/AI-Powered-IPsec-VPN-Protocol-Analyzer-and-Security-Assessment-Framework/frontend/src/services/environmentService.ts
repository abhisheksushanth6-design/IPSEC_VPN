/**
 * API service for Layer 01 — IPsec VPN Test Environment.
 *
 * Communicates with /api/environment to retrieve real VirtualBox hypervisor
 * state, host-only network details, VM lifecycle status, and verification evidence.
 */

import { appConfig } from '@/utils/config';
import { requestJson } from './httpClient';

export interface VirtualBoxInfo {
  installed: boolean;
  version: string | null;
  vboxmanage_path: string;
  error: string | null;
}

export interface HostOnlyNetworkInfo {
  available: boolean;
  name: string | null;
  ip_address: string | null;
  network_mask: string | null;
  status: string | null;
  error: string | null;
}

export interface VMInfo {
  name: string;
  uuid: string;
  role: 'client' | 'server' | 'analyzer' | 'other' | string;
  state: 'running' | 'poweroff' | 'paused' | 'saved' | 'aborted' | 'error' | string;
  os_type: string | null;
  mac_address: string | null;
  ip_addresses: string[];
  is_configured_role: boolean;
}

export interface EnvironmentHealthSummary {
  all_roles_discovered: boolean;
  running_count: number;
  total_count: number;
  network_ready: boolean;
}

export interface EnvironmentStatusResponse {
  layer_number: number;
  layer_name: string;
  layer_status: string;
  virtualbox: VirtualBoxInfo;
  host_only_network: HostOnlyNetworkInfo;
  vms: VMInfo[];
  health_summary: EnvironmentHealthSummary;
}

export interface VMActionResponse {
  success: boolean;
  vm_id: string;
  state: string;
  message: string;
  error: string | null;
}

export interface VerificationCheckItem {
  id: string;
  name: string;
  status: 'PASS' | 'WARNING' | 'FAIL' | 'UNKNOWN';
  evidence: string;
  error: string | null;
}

export interface EnvironmentVerificationResponse {
  timestamp: string;
  overall_status: 'PASS' | 'WARNING' | 'FAIL';
  checks: VerificationCheckItem[];
}

export interface EnvironmentEvidenceResponse {
  timestamp: string;
  virtualbox: Record<string, any>;
  network: Record<string, any>;
  vms: Array<Record<string, any>>;
  reachability: Record<string, any>;
  strongswan: Record<string, any>;
}

async function postJson<T>(path: string, body?: any): Promise<T> {
  const url = `${appConfig.apiBaseUrl}${path}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    let errorMsg = `Request failed with status ${response.status}`;
    try {
      const errBody = await response.json();
      if (errBody?.detail) errorMsg = errBody.detail;
      else if (errBody?.error) errorMsg = errBody.error;
    } catch {
      // Keep default error message
    }
    throw new Error(errorMsg);
  }

  return (await response.json()) as T;
}

export async function fetchEnvironmentStatus(): Promise<EnvironmentStatusResponse> {
  return requestJson<EnvironmentStatusResponse>('/api/environment/status');
}

export async function startVM(vmId: string): Promise<VMActionResponse> {
  return postJson<VMActionResponse>(`/api/environment/vm/${encodeURIComponent(vmId)}/start`);
}

export async function stopVM(vmId: string, force: boolean = false): Promise<VMActionResponse> {
  return postJson<VMActionResponse>(`/api/environment/vm/${encodeURIComponent(vmId)}/stop?force=${force}`);
}

export async function verifyEnvironment(): Promise<EnvironmentVerificationResponse> {
  return postJson<EnvironmentVerificationResponse>('/api/environment/verify');
}

export async function fetchEnvironmentEvidence(): Promise<EnvironmentEvidenceResponse> {
  return requestJson<EnvironmentEvidenceResponse>('/api/environment/evidence');
}

/** A testbed configuration profile (VM testbed and software testbed). */
export interface TestbedProfile {
  id: string;
  name: string;
  mode: 'TUNNEL' | 'TRANSPORT' | string;
  encryption: string;
  integrity: string;
  dh_group: string;
  dh_group_number?: number;
  pfs_enabled: boolean;
  ip_version: number;
  ike_version?: string;
  ipsec_protocol?: string;
  nat_traversal?: boolean;
  tfc_padding?: boolean;
  downgrade_demo?: boolean;
  traffic_type: string;
  security_rating?: string;
  compliance_standard?: string;
  description?: string;
  software_testbed?: boolean;
}

export interface SimulateProfileResponse {
  status: string;
  generator: string;
  profile_id: string;
  profile_name: string;
  capture_id: string;
  filename: string;
  packets_generated: number;
  packets_loaded: number;
  sessions_discovered: number;
  security_associations_discovered: number;
  mode: string;
  traffic_type: string;
  encryption: string;
  integrity: string;
  dh_group: number;
  pfs_enabled: boolean;
  ike_version: string;
  seed: number;
  ground_truth: Record<string, unknown>;
}

export async function fetchTestbedProfiles(): Promise<TestbedProfile[]> {
  return requestJson<TestbedProfile[]>('/api/environment/testbed-profiles');
}

/** Generate a capture for a profile with the software testbed and load it into the pipeline. */
export async function simulateTestbedProfile(
  profileId: string,
  options: { seed?: number; trafficType?: string; duration?: number; includeIke?: boolean } = {},
): Promise<SimulateProfileResponse> {
  const params = new URLSearchParams();
  if (options.seed !== undefined) params.set('seed', String(options.seed));
  if (options.trafficType) params.set('traffic_type', options.trafficType);
  if (options.duration !== undefined) params.set('duration', String(options.duration));
  if (options.includeIke !== undefined) params.set('include_ike', String(options.includeIke));
  const qs = params.toString();
  return postJson<SimulateProfileResponse>(
    `/api/environment/simulate-profile/${encodeURIComponent(profileId)}${qs ? `?${qs}` : ''}`,
  );
}
