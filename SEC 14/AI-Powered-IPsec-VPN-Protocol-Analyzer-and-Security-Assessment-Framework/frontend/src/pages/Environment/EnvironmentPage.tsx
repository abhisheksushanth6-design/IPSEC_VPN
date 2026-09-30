import {
  Activity,
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  Network,
  Play,
  RefreshCw,
  Server,
  Shield,
  Square,
  Terminal,
  XCircle,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { StatusKind } from '@/types';

import { PageContainer } from '@/components/layout';
import { ErrorState, LoadingState } from '@/components/states';
import { PageHeader, Panel } from '@/components/ui';
import {
  EnvironmentEvidenceResponse,
  EnvironmentStatusResponse,
  EnvironmentVerificationResponse,
  fetchEnvironmentEvidence,
  fetchEnvironmentStatus,
  fetchTestbedProfiles,
  SimulateProfileResponse,
  simulateTestbedProfile,
  startVM,
  stopVM,
  TestbedProfile,
  verifyEnvironment,
  VMInfo,
} from '@/services/environmentService';

export function EnvironmentPage() {
  const [status, setStatus] = useState<EnvironmentStatusResponse | null>(null);
  const [verification, setVerification] = useState<EnvironmentVerificationResponse | null>(null);
  const [evidence, setEvidence] = useState<EnvironmentEvidenceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [profiles, setProfiles] = useState<TestbedProfile[]>([]);
  const [simulatingProfile, setSimulatingProfile] = useState<string | null>(null);
  const [simulation, setSimulation] = useState<SimulateProfileResponse | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      setError(null);
      const data = await fetchEnvironmentStatus();
      setStatus(data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Failed to load environment status');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    let cancelled = false;
    fetchTestbedProfiles()
      .then((items) => {
        if (!cancelled) setProfiles(items.filter((p) => p.software_testbed));
      })
      .catch(() => {
        /* profile list is optional; the VM testbed cards still render */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSimulate = async (profile: TestbedProfile) => {
    setSimulatingProfile(profile.id);
    setActionMessage(null);
    try {
      const res = await simulateTestbedProfile(profile.id, { seed: Date.now() % 100000 });
      setSimulation(res);
      setActionMessage({
        type: 'success',
        text: `${res.profile_name}: ${res.packets_loaded} packets loaded as capture ${res.capture_id}, ${res.sessions_discovered} session(s) discovered.`,
      });
    } catch (err: any) {
      setActionMessage({ type: 'error', text: err?.message || 'Testbed generation failed' });
    } finally {
      setSimulatingProfile(null);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setActionMessage(null);
    try {
      const res = await verifyEnvironment();
      setVerification(res);
      await loadStatus();
      setActionMessage({ type: 'success', text: `Verification completed: ${res.overall_status}` });
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.response?.data?.detail || err?.message || 'Verification failed',
      });
    } finally {
      setVerifying(false);
    }
  };

  const handleStartVM = async (vmId: string) => {
    setActionLoading(vmId);
    setActionMessage(null);
    try {
      const res = await startVM(vmId);
      if (res.success) {
        setActionMessage({ type: 'success', text: res.message });
      } else {
        setActionMessage({ type: 'error', text: res.error || res.message });
      }
      await loadStatus();
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.response?.data?.detail || err?.message || `Failed to start VM ${vmId}`,
      });
    } finally {
      setActionLoading(null);
    }
  };

  const handleStopVM = async (vmId: string, force: boolean = false) => {
    setActionLoading(vmId);
    setActionMessage(null);
    try {
      const res = await stopVM(vmId, force);
      if (res.success) {
        setActionMessage({ type: 'success', text: res.message });
      } else {
        setActionMessage({ type: 'error', text: res.error || res.message });
      }
      await loadStatus();
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.response?.data?.detail || err?.message || `Failed to stop VM ${vmId}`,
      });
    } finally {
      setActionLoading(null);
    }
  };

  const handleLoadEvidence = async () => {
    try {
      const ev = await fetchEnvironmentEvidence();
      setEvidence(ev);
    } catch (err: any) {
      setActionMessage({
        type: 'error',
        text: err?.response?.data?.detail || err?.message || 'Failed to load evidence',
      });
    }
  };

  if (loading && !status) {
    return (
      <PageContainer>
        <LoadingState message="Discovering VirtualBox environment and network interfaces..." />
      </PageContainer>
    );
  }

  if (error && !status) {
    return (
      <PageContainer>
        <ErrorState message={error} onRetry={loadStatus} />
      </PageContainer>
    );
  }

  const clientVM = status?.vms?.find((v) => v.role === 'client');
  const serverVM = status?.vms?.find((v) => v.role === 'server');
  const analyzerVM = status?.vms?.find((v) => v.role === 'analyzer');

  // Compute status badge styles
  const getVMStateBadge = (vm?: VMInfo) => {
    if (!vm) return <span className="rounded bg-muted/20 px-2 py-0.5 text-xs text-muted">NOT CONFIGURED</span>;
    const s = vm.state.toLowerCase();
    if (s === 'running') {
      return (
        <span className="inline-flex items-center gap-1 rounded bg-success/20 px-2 py-0.5 text-xs font-medium text-success">
          <CheckCircle2 className="h-3 w-3" /> RUNNING
        </span>
      );
    }
    if (s === 'poweroff' || s === 'powered off') {
      return (
        <span className="inline-flex items-center gap-1 rounded bg-muted/30 px-2 py-0.5 text-xs font-medium text-muted">
          <Square className="h-3 w-3" /> POWERED OFF
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded bg-warning/20 px-2 py-0.5 text-xs font-medium text-warning">
        <AlertTriangle className="h-3 w-3" /> {s.toUpperCase()}
      </span>
    );
  };

  return (
    <PageContainer>
      <PageHeader
        title="Layer 01 — IPsec VPN Test Environment"
        description="VirtualBox hypervisor management, VM lifecycle control, host-only networking, and StrongSwan status verification."
        status={(status?.layer_status as StatusKind) || 'NOT INITIALIZED'}
        breadcrumbs={[{ label: 'System' }, { label: 'Test Environment' }]}
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleVerify}
              disabled={verifying}
              className="inline-flex items-center gap-2 rounded bg-info px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-info/90 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${verifying ? 'animate-spin' : ''}`} />
              {verifying ? 'Verifying...' : 'VERIFY ENVIRONMENT'}
            </button>
            <button
              type="button"
              onClick={loadStatus}
              className="inline-flex items-center gap-2 rounded border border-border px-3 py-1.5 text-sm text-secondary transition-colors hover:border-info hover:text-info"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        }
      />

      {actionMessage ? (
        <div
          className={`flex items-center gap-2 rounded border px-4 py-2.5 text-sm ${actionMessage.type === 'success'
              ? 'border-success/30 bg-success/10 text-success'
              : 'border-danger/30 bg-danger/10 text-danger'
            }`}
        >
          {actionMessage.type === 'success' ? (
            <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
          ) : (
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
          )}
          <span>{actionMessage.text}</span>
        </div>
      ) : null}

      {/* Primary Status Matrix */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* VirtualBox Card */}
        <Panel className="flex flex-col justify-between p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">VirtualBox</span>
            <Server className="h-4 w-4 text-secondary" />
          </div>
          <div className="my-2">
            <div className="text-lg font-bold text-primary">
              {status?.virtualbox?.installed ? (
                <span className="text-success">READY</span>
              ) : (
                <span className="text-danger">ERROR</span>
              )}
            </div>
            <div className="text-xs text-muted">
              {status?.virtualbox?.installed
                ? `Version: ${status.virtualbox.version}`
                : status?.virtualbox?.error || 'VBoxManage not found'}
            </div>
          </div>
          <div className="truncate text-2xs text-muted" title={status?.virtualbox?.vboxmanage_path}>
            {status?.virtualbox?.vboxmanage_path}
          </div>
        </Panel>

        {/* Host-Only Network Card */}
        <Panel className="flex flex-col justify-between p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">Host-Only Network</span>
            <Network className="h-4 w-4 text-secondary" />
          </div>
          <div className="my-2">
            <div className="text-lg font-bold text-primary">
              {status?.host_only_network?.available ? (
                <span className="text-success">AVAILABLE</span>
              ) : (
                <span className="text-danger">ERROR</span>
              )}
            </div>
            <div className="text-xs text-muted">
              {status?.host_only_network?.ip_address
                ? `${status.host_only_network.ip_address}/${status.host_only_network.network_mask || '24'}`
                : 'No IP assigned'}
            </div>
          </div>
          <div className="truncate text-2xs text-muted">
            {status?.host_only_network?.name || 'Adapter not detected'}
          </div>
        </Panel>

        {/* StrongSwan Daemon Status */}
        <Panel className="flex flex-col justify-between p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">StrongSwan Service</span>
            <Shield className="h-4 w-4 text-secondary" />
          </div>
          <div className="my-2">
            <div className="text-lg font-bold text-primary">
              {serverVM?.state === 'running' || clientVM?.state === 'running' ? (
                <span className="text-info">UNKNOWN</span>
              ) : (
                <span className="text-muted">NOT FOUND</span>
              )}
            </div>
            <div className="text-xs text-muted">
              {serverVM?.state === 'running'
                ? 'VM running · Guest credentials needed for charon'
                : 'VMs powered off'}
            </div>
          </div>
          <div className="text-2xs text-muted">Charon IKEv2 Daemon</div>
        </Panel>

        {/* IPsec SA Posture */}
        <Panel className="flex flex-col justify-between p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted">IPsec Tunnel</span>
            <Activity className="h-4 w-4 text-secondary" />
          </div>
          <div className="my-2">
            <div className="text-lg font-bold text-primary">
              {serverVM?.state === 'running' && clientVM?.state === 'running' ? (
                <span className="text-info">UNKNOWN</span>
              ) : (
                <span className="text-muted">NO SA</span>
              )}
            </div>
            <div className="text-xs text-muted">
              {serverVM?.state === 'running' && clientVM?.state === 'running'
                ? 'Traffic inspection ready'
                : 'Peers not running simultaneously'}
            </div>
          </div>
          <div className="text-2xs text-muted">IKEv2 / ESP SA State</div>
        </Panel>
      </div>

      {/* VM Lifecycle Control Grid */}
      <section aria-labelledby="vms-heading" className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 id="vms-heading" className="text-base font-semibold text-primary">
            Virtual Machine Cluster
          </h2>
          <span className="text-xs text-muted">
            Running: {status?.health_summary?.running_count ?? 0} / {status?.health_summary?.total_count ?? 0}
          </span>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {[
            { roleLabel: 'Client VM', vm: clientVM, defaultName: 'IPsec-Client' },
            { roleLabel: 'Server VM', vm: serverVM, defaultName: 'IPsec-Server' },
            { roleLabel: 'Analyzer VM', vm: analyzerVM, defaultName: 'Name: IPsec-Analyzer' },
          ].map(({ roleLabel, vm, defaultName }) => {
            const isTarget = actionLoading === (vm?.uuid || vm?.name || defaultName);
            const isRunning = vm?.state.toLowerCase() === 'running';

            return (
              <Panel key={roleLabel} className="space-y-4 p-5">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider text-muted">{roleLabel}</div>
                    <div className="text-base font-bold text-primary">{vm?.name || defaultName}</div>
                  </div>
                  {getVMStateBadge(vm)}
                </div>

                <div className="space-y-1.5 text-xs text-secondary">
                  <div className="flex justify-between">
                    <span className="text-muted">OS Type:</span>
                    <span>{vm?.os_type || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">MAC Address:</span>
                    <span className="font-mono text-2xs">{vm?.mac_address || 'Not assigned'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">IP Addresses:</span>
                    <span className="font-mono text-2xs">
                      {vm?.ip_addresses && vm.ip_addresses.length > 0
                        ? vm.ip_addresses.join(', ')
                        : 'None discovered'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">UUID:</span>
                    <span className="font-mono text-2xs truncate max-w-[140px]" title={vm?.uuid}>
                      {vm?.uuid || 'N/A'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-2 border-t border-border">
                  {isRunning ? (
                    <>
                      <button
                        type="button"
                        onClick={() => vm && handleStopVM(vm.uuid || vm.name, false)}
                        disabled={isTarget || !vm}
                        className="inline-flex flex-1 items-center justify-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs font-medium text-warning hover:border-warning hover:bg-warning/10 disabled:opacity-50"
                      >
                        <Square className="h-3.5 w-3.5" />
                        {isTarget ? 'Stopping...' : 'ACPI Stop'}
                      </button>
                      <button
                        type="button"
                        onClick={() => vm && handleStopVM(vm.uuid || vm.name, true)}
                        disabled={isTarget || !vm}
                        className="inline-flex items-center justify-center rounded border border-danger/40 px-2 py-1.5 text-xs font-medium text-danger hover:bg-danger/10 disabled:opacity-50"
                        title="Force Power Off"
                      >
                        Force
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      onClick={() => vm && handleStartVM(vm.uuid || vm.name)}
                      disabled={isTarget || !vm}
                      className="inline-flex flex-1 items-center justify-center gap-1.5 rounded bg-info px-3 py-1.5 text-xs font-medium text-white hover:bg-info/90 disabled:opacity-50"
                    >
                      <Play className="h-3.5 w-3.5" />
                      {isTarget ? 'Starting...' : 'Start VM'}
                    </button>
                  )}
                </div>
              </Panel>
            );
          })}
        </div>
      </section>

      {/* Environment Verification Results */}
      {verification ? (
        <section aria-labelledby="verification-heading" className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 id="verification-heading" className="text-base font-semibold text-primary">
              Live Verification Results
            </h2>
            <span
              className={`rounded px-2.5 py-0.5 text-xs font-bold ${verification.overall_status === 'PASS'
                  ? 'bg-success/20 text-success'
                  : verification.overall_status === 'WARNING'
                    ? 'bg-warning/20 text-warning'
                    : 'bg-danger/20 text-danger'
                }`}
            >
              OVERALL: {verification.overall_status}
            </span>
          </div>

          <div className="divide-y divide-border rounded-lg border border-border bg-card">
            {verification.checks.map((check) => (
              <div key={check.id} className="flex items-start gap-3 p-3.5">
                <div className="pt-0.5">
                  {check.status === 'PASS' ? (
                    <CheckCircle2 className="h-4 w-4 text-success" />
                  ) : check.status === 'WARNING' ? (
                    <AlertTriangle className="h-4 w-4 text-warning" />
                  ) : check.status === 'FAIL' ? (
                    <XCircle className="h-4 w-4 text-danger" />
                  ) : (
                    <AlertCircle className="h-4 w-4 text-muted" />
                  )}
                </div>
                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-primary">{check.name}</span>
                    <span
                      className={`text-2xs font-bold uppercase ${check.status === 'PASS'
                          ? 'text-success'
                          : check.status === 'WARNING'
                            ? 'text-warning'
                            : check.status === 'FAIL'
                              ? 'text-danger'
                              : 'text-muted'
                        }`}
                    >
                      {check.status}
                    </span>
                  </div>
                  <p className="text-xs text-secondary">{check.evidence}</p>
                  {check.error ? <p className="text-2xs text-danger">{check.error}</p> : null}
                </div>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {/* Software testbed — reproducible IPsec configurations without a hypervisor */}
      <section aria-labelledby="testbed-heading" className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 id="testbed-heading" className="text-base font-semibold text-primary">
            Software Testbed — Reproducible IPsec Configurations
          </h2>
          <span className="text-2xs text-muted">
            Real RFC 4303 ESP framing with real encryption; ground truth registered for every capture.
          </span>
        </div>
        {profiles.length === 0 ? (
          <p className="text-xs text-muted">
            No software testbed profiles were reported by the backend.
          </p>
        ) : (
          <Panel className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border text-muted">
                  <tr>
                    <th className="px-3 py-2">Profile</th>
                    <th className="px-3 py-2">Mode</th>
                    <th className="px-3 py-2">IKE</th>
                    <th className="px-3 py-2">Encryption / Integrity</th>
                    <th className="px-3 py-2">DH</th>
                    <th className="px-3 py-2">PFS</th>
                    <th className="px-3 py-2">IP</th>
                    <th className="px-3 py-2">Traffic</th>
                    <th className="px-3 py-2">Expected</th>
                    <th className="px-3 py-2" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {profiles.map((p) => (
                    <tr key={p.id}>
                      <td className="px-3 py-2">
                        <div className="font-semibold text-primary">{p.name}</div>
                        <div className="font-mono text-2xs text-muted">{p.id}</div>
                      </td>
                      <td className="px-3 py-2 text-secondary">{p.mode}{p.nat_traversal ? ' · NAT-T' : ''}{p.tfc_padding ? ' · TFC' : ''}</td>
                      <td className="px-3 py-2 text-secondary">{p.ike_version ?? '—'}</td>
                      <td className="px-3 py-2 text-secondary">{p.encryption} / {p.integrity}</td>
                      <td className="px-3 py-2 text-secondary">{p.dh_group}</td>
                      <td className="px-3 py-2 text-secondary">{p.pfs_enabled ? 'on' : 'off'}</td>
                      <td className="px-3 py-2 text-secondary">IPv{p.ip_version}</td>
                      <td className="px-3 py-2 text-secondary">{p.traffic_type}</td>
                      <td className="px-3 py-2">
                        <span className={`text-2xs font-semibold ${p.security_rating === 'STRONG' ? 'text-success' : p.security_rating === 'WEAK' ? 'text-danger' : 'text-warning'}`}>
                          {p.security_rating ?? '—'}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <button
                          type="button"
                          onClick={() => handleSimulate(p)}
                          disabled={simulatingProfile !== null}
                          className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1 text-xs text-secondary hover:border-info hover:text-info disabled:opacity-50"
                        >
                          <FlaskConical className={`h-3.5 w-3.5 ${simulatingProfile === p.id ? 'animate-pulse' : ''}`} />
                          {simulatingProfile === p.id ? 'Generating…' : 'Generate & load'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
        {simulation ? (
          <Panel className="p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="text-secondary">
                <span className="font-semibold text-primary">{simulation.profile_name}</span> → capture{' '}
                <span className="font-mono">{simulation.capture_id}</span> · {simulation.packets_loaded} packets ·{' '}
                {simulation.sessions_discovered} session(s) · {simulation.security_associations_discovered} SA(s) · seed {simulation.seed}
              </div>
              <Link
                to="/security-posture"
                className="inline-flex items-center gap-1.5 rounded bg-info px-2.5 py-1 text-xs font-medium text-white hover:bg-info/90"
              >
                <Shield className="h-3.5 w-3.5" /> Assess security posture
              </Link>
            </div>
          </Panel>
        ) : null}
      </section>

      {/* Evidence Snapshot Explorer */}
      <section aria-labelledby="evidence-heading" className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 id="evidence-heading" className="text-base font-semibold text-primary">
            Factual Evidence Collection
          </h2>
          <button
            type="button"
            onClick={handleLoadEvidence}
            className="inline-flex items-center gap-1.5 rounded border border-border px-2.5 py-1 text-xs text-secondary hover:border-info hover:text-info"
          >
            <Terminal className="h-3.5 w-3.5" />
            Inspect Evidence JSON
          </button>
        </div>

        {evidence ? (
          <Panel className="p-4">
            <pre className="max-h-96 overflow-auto font-mono text-2xs text-secondary leading-relaxed bg-black/40 p-3 rounded">
              {JSON.stringify(evidence, null, 2)}
            </pre>
          </Panel>
        ) : (
          <p className="text-xs text-muted">
            Click "Inspect Evidence JSON" to view the raw factual evidence collected by Layer 01.
          </p>
        )}
      </section>
    </PageContainer>
  );
}
