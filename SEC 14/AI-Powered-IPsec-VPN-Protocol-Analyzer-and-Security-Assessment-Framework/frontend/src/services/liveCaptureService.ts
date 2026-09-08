/**
 * API client service for Layer 02 — Packet Capture & Data Collection.
 *
 * Controls real hypervisor NIC tracing, queries live interface availability,
 * retrieves genuine packet statistics and elapsed duration, and stops/ingests captures.
 */

import { appConfig } from '@/utils/config';
import { requestJson } from './httpClient';

export interface CaptureSourceInterface {
  vm_name: string;
  vm_uuid: string;
  vm_state: string;
  role: string;
  nic_number: number;
  nic_type: string;
  adapter_name: string | null;
  mac_address: string | null;
  is_recommended: boolean;
}

export interface LiveCaptureInterfacesResponse {
  interfaces: CaptureSourceInterface[];
  default_vm: string | null;
  default_nic: number | null;
}

export interface LiveCaptureStatusResponse {
  state: 'IDLE' | 'STARTING' | 'CAPTURING' | 'STOPPING' | 'INGESTING' | 'COMPLETED' | 'ERROR' | string;
  capture_id: string | null;
  source_vm: string | null;
  nic_number: number | null;
  output_file: string | null;
  started_at: string | null;
  elapsed_seconds: number;
  packet_count: number;
  file_size_bytes: number;
  error: string | null;
}

export interface StopCaptureResponse {
  capture_id: string;
  pcap_path: string;
  packet_count: number;
  file_size_bytes: number;
  ingestion_status: string;
  analysis_id: string | null;
  sessions_discovered: number;
  error: string | null;
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
      else if (errBody?.message) errorMsg = errBody.message;
    } catch {
      // Keep default error message
    }
    throw new Error(errorMsg);
  }

  return (await response.json()) as T;
}

export async function fetchLiveCaptureStatus(): Promise<LiveCaptureStatusResponse> {
  return requestJson<LiveCaptureStatusResponse>('/api/live-capture/status');
}

export async function fetchLiveCaptureInterfaces(): Promise<LiveCaptureInterfacesResponse> {
  return requestJson<LiveCaptureInterfacesResponse>('/api/live-capture/interfaces');
}

export async function startLiveCapture(vm: string, nic?: number): Promise<LiveCaptureStatusResponse> {
  return postJson<LiveCaptureStatusResponse>('/api/live-capture/start', { vm, nic });
}

export async function stopLiveCapture(): Promise<StopCaptureResponse> {
  return postJson<StopCaptureResponse>('/api/live-capture/stop');
}
