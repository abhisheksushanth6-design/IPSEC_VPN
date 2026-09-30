import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity,
  PhoneCall,
  MessageCircle,
  Mail,
  Video,
  Layers,
  Sparkles,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  Info,
  ChevronRight,
  X,
  Globe,
} from 'lucide-react';
import { trafficAnalysisService } from '@/services/trafficAnalysisService';
import type {
  TrafficClassificationItem,
  TrafficClassificationSummary,
  TrafficType,
} from '@/types';

export const TrafficAnalysisPage: React.FC = () => {
  const [classifications, setClassifications] = useState<TrafficClassificationItem[]>([]);
  const [summary, setSummary] = useState<TrafficClassificationSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [reclassifying, setReclassifying] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedItem, setSelectedItem] = useState<TrafficClassificationItem | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      setError(null);
      const [distRes, itemsRes] = await Promise.all([
        trafficAnalysisService.getDistribution().catch(() => null),
        trafficAnalysisService.getCaptureClassifications('default').catch(() => []),
      ]);

      if (distRes) {
        setSummary(distRes);
      }
      setClassifications(itemsRes || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load traffic classification telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleTriggerAnalysis = async () => {
    try {
      setReclassifying(true);
      const updated = await trafficAnalysisService.classifyCapture('default');
      setClassifications(updated);
      const newSummary = await trafficAnalysisService.getDistribution();
      setSummary(newSummary);
    } catch (err: any) {
      setError(err.message || 'Failed to trigger AI traffic classification');
    } finally {
      setReclassifying(false);
    }
  };

  const safeClassifications = Array.isArray(classifications) ? classifications : [];

  const filteredItems = useMemo(() => {
    return safeClassifications.filter((item) => {
      const matchesSearch =
        !searchQuery ||
        item.session_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.flow_id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = selectedType === 'ALL' || item.traffic_type === selectedType;
      return matchesSearch && matchesType;
    });
  }, [safeClassifications, searchQuery, selectedType]);

  const getTypeColor = (type: TrafficType | string) => {
    switch (type) {
      case 'VOIP':
        return {
          badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          dot: 'bg-emerald-400',
          gradient: 'from-emerald-600/20 to-emerald-900/10',
          border: 'border-emerald-500/20',
          text: 'text-emerald-400',
        };
      case 'WHATSAPP':
        return {
          badge: 'bg-green-500/10 text-green-400 border-green-500/30',
          dot: 'bg-green-400',
          gradient: 'from-green-600/20 to-green-900/10',
          border: 'border-green-500/20',
          text: 'text-green-400',
        };
      case 'EMAIL':
        return {
          badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          dot: 'bg-amber-400',
          gradient: 'from-amber-600/20 to-amber-900/10',
          border: 'border-amber-500/20',
          text: 'text-amber-400',
        };
      case 'VIDEO_STREAMING':
      case 'VIDEO':
        return {
          badge: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
          dot: 'bg-purple-400',
          gradient: 'from-purple-600/20 to-purple-900/10',
          border: 'border-purple-500/20',
          text: 'text-purple-400',
        };
      case 'WEB_BROWSING':
      case 'WEB':
        return {
          badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
          dot: 'bg-cyan-400',
          gradient: 'from-cyan-600/20 to-cyan-900/10',
          border: 'border-cyan-500/20',
          text: 'text-cyan-400',
        };
      case 'ICMP':
        return {
          badge: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
          dot: 'bg-sky-400',
          gradient: 'from-sky-600/20 to-sky-900/10',
          border: 'border-sky-500/20',
          text: 'text-sky-400',
        };
      default:
        return {
          badge: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          dot: 'bg-slate-400',
          gradient: 'from-slate-600/20 to-slate-900/10',
          border: 'border-slate-500/20',
          text: 'text-slate-400',
        };
    }
  };

  const getTypeIcon = (type: TrafficType | string) => {
    switch (type) {
      case 'VOIP':
        return <PhoneCall className="w-4 h-4 text-emerald-400" />;
      case 'WHATSAPP':
        return <MessageCircle className="w-4 h-4 text-green-400" />;
      case 'EMAIL':
        return <Mail className="w-4 h-4 text-amber-400" />;
      case 'VIDEO_STREAMING':
      case 'VIDEO':
        return <Video className="w-4 h-4 text-purple-400" />;
      case 'WEB_BROWSING':
      case 'WEB':
        return <Globe className="w-4 h-4 text-cyan-400" />;
      default:
        return <Activity className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider bg-sky-500/10 text-sky-400 border border-sky-500/20">
              Layer 07 &middot; AI Traffic Classification
            </span>
            <span className="text-xs text-slate-400">RFC 4303 Encapsulated Payload Inference</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <Sparkles className="w-7 h-7 text-sky-400" />
            AI-Based Protocol &amp; Traffic Classification
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Supervised machine learning traffic classifier predicting encapsulated payload categories
            (VoIP, WhatsApp/Messaging, Email, Web Browsing, ICMP, Video Streaming, Other) from non-payload
            observable flow characteristics and session fingerprints without decryption.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchData()}
            disabled={loading}
            className="px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleTriggerAnalysis}
            disabled={reclassifying}
            className="px-4 py-2 text-xs font-semibold text-white bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 rounded-lg shadow-lg shadow-sky-900/20 flex items-center gap-2 transition-all disabled:opacity-50"
          >
            <Sparkles className={`w-4 h-4 ${reclassifying ? 'animate-pulse' : ''}`} />
            {reclassifying ? 'Classifying ESP Flows...' : 'Classify Capture Flows'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
          <p className="text-sm">{error}</p>
        </div>
      )}

      {/* 5 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Classified */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-sky-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Total Evaluated</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.total_classified ?? classifications.length}
          </div>
          <div className="text-xs text-slate-400 flex items-center gap-1">
            <span>Avg Conf:</span>
            <span className="font-semibold text-sky-400">
              {summary?.average_confidence ? `${(summary.average_confidence * 100).toFixed(1)}%` : 'N/A'}
            </span>
          </div>
        </div>

        {/* VoIP */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-emerald-500/20 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-xs text-emerald-400 mb-2">
            <span className="font-semibold">VoIP Telephony</span>
            <PhoneCall className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.voip_count ?? safeClassifications.filter((c) => c.traffic_type === 'VOIP').length}
          </div>
          <div className="text-xs text-slate-400">20ms cadence &middot; G.107 MOS</div>
        </div>

        {/* WhatsApp */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-green-500/20 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-green-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-xs text-green-400 mb-2">
            <span className="font-semibold">WhatsApp Messaging</span>
            <MessageCircle className="w-4 h-4 text-green-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.whatsapp_count ?? safeClassifications.filter((c) => c.traffic_type === 'WHATSAPP').length}
          </div>
          <div className="text-xs text-slate-400">Burst pairs &middot; Keepalives</div>
        </div>

        {/* Email */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-amber-500/20 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-xs text-amber-400 mb-2">
            <span className="font-semibold">E-mail Transfer</span>
            <Mail className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.email_count ?? safeClassifications.filter((c) => c.traffic_type === 'EMAIL').length}
          </div>
          <div className="text-xs text-slate-400">Cmd-resp &middot; Bulk trains</div>
        </div>

        {/* Video Streaming */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-purple-500/20 backdrop-blur-sm shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-purple-500/5 rounded-full blur-xl pointer-events-none" />
          <div className="flex items-center justify-between text-xs text-purple-400 mb-2">
            <span className="font-semibold">Video Streaming</span>
            <Video className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {summary?.video_streaming_count ?? safeClassifications.filter((c) => c.traffic_type === 'VIDEO_STREAMING').length}
          </div>
          <div className="text-xs text-slate-400">Periodic chunks &middot; MTU downlink</div>
        </div>
      </div>

      {/* Distribution Progress Bar */}
      {summary && summary.total_classified > 0 && (
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span className="font-semibold text-slate-200">ESP Encapsulated Traffic Distribution</span>
            <span>{summary.total_classified} total classified flows</span>
          </div>
          <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden flex">
            {summary.voip_count > 0 && (
              <div
                style={{ width: `${(summary.voip_count / summary.total_classified) * 100}%` }}
                className="bg-emerald-500 h-full transition-all"
                title={`VoIP: ${summary.voip_count}`}
              />
            )}
            {summary.whatsapp_count > 0 && (
              <div
                style={{ width: `${(summary.whatsapp_count / summary.total_classified) * 100}%` }}
                className="bg-green-500 h-full transition-all"
                title={`WhatsApp: ${summary.whatsapp_count}`}
              />
            )}
            {summary.email_count > 0 && (
              <div
                style={{ width: `${(summary.email_count / summary.total_classified) * 100}%` }}
                className="bg-amber-500 h-full transition-all"
                title={`Email: ${summary.email_count}`}
              />
            )}
            {summary.video_streaming_count > 0 && (
              <div
                style={{ width: `${(summary.video_streaming_count / summary.total_classified) * 100}%` }}
                className="bg-purple-500 h-full transition-all"
                title={`Video Streaming: ${summary.video_streaming_count}`}
              />
            )}
            {summary.generic_count > 0 && (
              <div
                style={{ width: `${(summary.generic_count / summary.total_classified) * 100}%` }}
                className="bg-slate-500 h-full transition-all"
                title={`Generic: ${summary.generic_count}`}
              />
            )}
          </div>
          <div className="flex flex-wrap items-center gap-4 mt-3 text-xs">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> VoIP ({summary.voip_count})
            </span>
            <span className="flex items-center gap-1.5 text-green-400">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500" /> WhatsApp ({summary.whatsapp_count})
            </span>
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Email ({summary.email_count})
            </span>
            <span className="flex items-center gap-1.5 text-purple-400">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" /> Video Streaming ({summary.video_streaming_count})
            </span>
            <span className="flex items-center gap-1.5 text-slate-400">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-500" /> Generic ({summary.generic_count})
            </span>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by session or flow ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
          {['ALL', 'VOIP', 'WHATSAPP', 'EMAIL', 'VIDEO_STREAMING', 'GENERIC'].map((t) => (
            <button
              key={t}
              onClick={() => setSelectedType(t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${selectedType === t
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 bg-slate-800/40 border border-transparent'
                }`}
            >
              {t.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Classifications Table */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3">Session / Flow</th>
                <th className="px-4 py-3">Traffic Type</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Key Explainability Signals</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {loading && classifications.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-sky-400" />
                    Loading encrypted flow telemetry...
                  </td>
                </tr>
              ) : filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-slate-500">
                    <Info className="w-6 h-6 mx-auto mb-2 text-slate-400" />
                    No classified traffic flows match the current filters.
                  </td>
                </tr>
              ) : (
                filteredItems.map((item) => {
                  const style = getTypeColor(item.traffic_type);
                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                      onClick={() => setSelectedItem(item)}
                    >
                      <td className="px-4 py-3 font-mono text-slate-300">
                        <div className="font-semibold text-slate-200">{item.session_id || 'Session'}</div>
                        <div className="text-[10px] text-slate-500 truncate max-w-xs">{item.flow_id}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${style.badge}`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                          {getTypeIcon(item.traffic_type)}
                          {item.traffic_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              style={{ width: `${item.confidence * 100}%` }}
                              className={`h-full ${item.confidence >= 0.85
                                  ? 'bg-emerald-500'
                                  : item.confidence >= 0.7
                                    ? 'bg-amber-500'
                                    : 'bg-slate-500'
                                }`}
                            />
                          </div>
                          <span className="font-mono text-slate-300 font-medium">
                            {(item.confidence * 100).toFixed(1)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1.5 max-w-lg">
                          {item.explainability?.slice(0, 3).map((exp, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-[11px] text-slate-300"
                              title={exp.description || ''}
                            >
                              <span className="text-slate-400 font-medium">{exp.signal || exp.feature}:</span>{' '}
                              <span className="text-sky-300">{exp.value}</span>
                            </span>
                          ))}
                          {(!item.explainability || item.explainability.length === 0) && (
                            <span className="text-slate-500 text-[11px]">Statistical heuristic attribution</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedItem(item);
                          }}
                          className="px-2.5 py-1 rounded text-xs font-medium text-sky-400 hover:text-sky-300 hover:bg-sky-500/10 border border-transparent hover:border-sky-500/20 transition-all flex items-center gap-1 ml-auto"
                        >
                          Inspect
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Explainability Drawer / Modal */}
      {selectedItem && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                {getTypeIcon(selectedItem.traffic_type)}
                <div>
                  <h3 className="text-lg font-bold text-white">Flow AI Explainability</h3>
                  <p className="text-xs text-slate-400 font-mono">{selectedItem.session_id}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedItem(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Classification Verdict Card */}
            <div
              className={`p-4 rounded-xl border bg-gradient-to-br ${getTypeColor(selectedItem.traffic_type).gradient
                } ${getTypeColor(selectedItem.traffic_type).border}`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs uppercase font-bold text-slate-300">Predicted Classification</span>
                <span className="text-xs font-bold text-sky-400 font-mono">
                  {(selectedItem.confidence * 100).toFixed(1)}% Confidence
                </span>
              </div>
              <div className="text-2xl font-bold text-white flex items-center gap-2">
                {selectedItem.traffic_type.replace('_', ' ')}
              </div>
              <p className="text-xs text-slate-300 mt-2">
                Evaluated from side-channel metrics (timing cadence, packet size distribution, directional asymmetry)
                without breaking RFC 4303 ESP encryption.
              </p>
            </div>

            {/* Multi-Class Probabilities */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Multi-Class Probability Distribution
              </h4>
              <div className="space-y-2">
                {Object.entries(selectedItem.probabilities || {}).map(([label, prob]) => (
                  <div key={label} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-300 font-medium">{label.replace('_', ' ')}</span>
                      <span className="font-mono text-slate-400">{(prob * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        style={{ width: `${prob * 100}%` }}
                        className={`h-full ${label === selectedItem.traffic_type ? 'bg-sky-500' : 'bg-slate-600'
                          }`}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Empirical Features Extracted */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Empirical Features Inside ESP Tunnel
              </h4>
              <div className="grid grid-cols-2 gap-3 text-xs">
                {Object.entries(selectedItem.features || {}).map(([k, v]) => (
                  <div key={k} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80">
                    <div className="text-slate-400 text-[11px] truncate mb-0.5">{k.replace(/_/g, ' ')}</div>
                    <div className="font-mono font-semibold text-slate-200 truncate">
                      {typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : String(v)}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Explainability Signals */}
            <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                Decision Attribution Evidence
              </h4>
              <div className="space-y-2">
                {selectedItem.explainability?.map((exp, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 flex items-start gap-3">
                    <CheckCircle2 className="w-4 h-4 text-sky-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                        <span>{exp.signal || exp.feature}</span>
                        <span className="font-mono text-sky-400 font-normal">[{String(exp.value)}]</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{exp.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
