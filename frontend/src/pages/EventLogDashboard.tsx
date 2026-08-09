import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import { eventLogService } from "../services/events";
import type { SecurityEventItem, SecurityEventSummary, AuthTimelineItem, AttackChainItem } from "../services/events";

export const EventLogDashboard: React.FC = () => {
  const { logout } = useAuth();
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [summary, setSummary] = useState<SecurityEventSummary | null>(null);
  const [_timeline, setTimeline] = useState<AuthTimelineItem[]>([]);
  const [attackChain, setAttackChain] = useState<AttackChainItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Phase 5 Required Filters: User, Device, Severity, Event Type, Date
  const [userFilter, setUserFilter] = useState<string>("");
  const [deviceFilter, setDeviceFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("ALL");
  const [dateFilter, setDateFilter] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [showSimulateModal, setShowSimulateModal] = useState<boolean>(false);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [actionExecuting, setActionExecuting] = useState<boolean>(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [eventsRes, summaryRes, timelineRes, chainRes] = await Promise.all([
        eventLogService.getEvents({
          username: userFilter || undefined,
          device_id: deviceFilter || undefined,
          level: severityFilter !== "ALL" ? severityFilter : undefined,
          event_type: eventTypeFilter !== "ALL" ? eventTypeFilter : undefined,
          date_range: dateFilter !== "ALL" ? dateFilter : undefined,
          search: searchTerm || undefined,
          limit: 100,
        }),
        eventLogService.getSummary(deviceFilter || undefined),
        eventLogService.getAuthTimeline(deviceFilter || undefined, 25),
        eventLogService.getAttackChainTimeline(deviceFilter || undefined, 15),
      ]);

      setEvents(eventsRes.items);
      setSummary(summaryRes);
      setTimeline(timelineRes);
      setAttackChain(chainRes);
    } catch (err: any) {
      console.error("Failed to load OS event data:", err);
      setError(err.response?.data?.detail || "Failed to load OS security logs.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [severityFilter, eventTypeFilter, dateFilter]);

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchData();
  };

  const handleSimulate = async (
    scenario: "BRUTE_FORCE" | "PRIVILEGE_ESCALATION" | "ACCOUNT_DISABLED" | "OFF_HOURS" | "PERSISTENCE" | "LOG_CLEARING" | "ATTACK_CHAIN"
  ) => {
    try {
      setSimulating(true);
      const res = await eventLogService.triggerSimulate(scenario);
      setFeedback(`Simulation triggered: ${res.scenario} injected ${res.events_injected || res.steps_injected} event(s)!`);
      setShowSimulateModal(false);
      fetchData();
    } catch (err: any) {
      setFeedback(`Simulation failed: ${err.message}`);
    } finally {
      setSimulating(false);
      setTimeout(() => setFeedback(null), 5000);
    }
  };

  // Phase 6 Response Actions
  const handleResponseAction = async (
    actionType: "DISABLE_USER" | "FORCE_LOGOUT" | "INVESTIGATE" | "IGNORE" | "ALLOWLIST",
    evt: SecurityEventItem
  ) => {
    try {
      setActionExecuting(true);
      const res = await eventLogService.executeResponseAction({
        action_type: actionType,
        device_id: evt.device_id,
        username: evt.username || undefined,
        event_id: evt.event_id,
      });

      setFeedback(`[AUDITED] Action '${actionType}' executed for user '${evt.username || "system"}'. Action ID: ${res.action_id}`);
      setSelectedEvent(null);
      fetchData();
    } catch (err: any) {
      setFeedback(`Action failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setActionExecuting(false);
      setTimeout(() => setFeedback(null), 6000);
    }
  };

  const getSeverityBadgeClass = (level: string) => {
    switch (level) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border-red-500/30";
      case "Error":
      case "Warning":
        return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "Information":
      default:
        return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    }
  };

  const getChainBadgeStyle = (badgeType: string) => {
    switch (badgeType) {
      case "FAILED_LOGIN":
        return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "ADMIN_LOGIN":
        return "bg-purple-500/20 text-purple-400 border-purple-500/30";
      case "PERSISTENCE":
        return "bg-cyan-500/20 text-cyan-400 border-cyan-500/30";
      case "CRITICAL_ALERT":
        return "bg-red-500/30 text-red-400 border-red-500 font-bold animate-pulse";
      case "USER_LOGIN":
      default:
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Header Bar */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center space-x-4">
          <Link to="/" className="text-xl font-extrabold tracking-wider bg-gradient-to-r from-blue-400 via-indigo-400 to-cyan-400 bg-clip-text text-transparent">
            SentinelX EDR
          </Link>
          <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
            Security Events & Auth Console
          </span>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => setShowSimulateModal(true)}
            className="px-3.5 py-1.5 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white rounded-lg text-sm font-medium shadow-lg shadow-indigo-500/20 transition-all flex items-center space-x-2"
          >
            <span>⚡ Simulate Attack Scenario</span>
          </button>
          <WebSocketStatusBadge />
          <NotificationCenter />
          <button
            onClick={logout}
            className="px-3 py-1.5 text-sm font-medium text-slate-400 hover:text-white bg-slate-800/80 hover:bg-slate-800 rounded-lg border border-slate-700 transition-colors"
          >
            Logout
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Navigation Tabs */}
        <nav className="flex space-x-2 border-b border-slate-800 pb-3">
          <Link to="/threats" className="px-3.5 py-1.5 text-sm font-medium text-slate-400 hover:text-white rounded-lg transition-colors">
            Threats
          </Link>
          <Link to="/integrity" className="px-3.5 py-1.5 text-sm font-medium text-slate-400 hover:text-white rounded-lg transition-colors">
            File Integrity (FIM)
          </Link>
          <Link to="/processes" className="px-3.5 py-1.5 text-sm font-medium text-slate-400 hover:text-white rounded-lg transition-colors">
            Processes
          </Link>
          <Link to="/network" className="px-3.5 py-1.5 text-sm font-medium text-slate-400 hover:text-white rounded-lg transition-colors">
            Network Connections
          </Link>
          <span className="px-3.5 py-1.5 text-sm font-medium text-cyan-400 bg-slate-800/90 rounded-lg border border-slate-700">
            Security Events (/events)
          </span>
          <Link to="/respond" className="px-3.5 py-1.5 text-sm font-medium text-slate-400 hover:text-white rounded-lg transition-colors">
            Response Console
          </Link>
        </nav>

        {feedback && (
          <div className="p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-sm flex items-center justify-between shadow-md">
            <span>{feedback}</span>
            <button onClick={() => setFeedback(null)} className="text-indigo-400 hover:text-white">✕</button>
          </div>
        )}

        {/* Phase 5 Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Logins</p>
            <p className="text-3xl font-extrabold text-emerald-400 mt-2">{summary?.logins ?? 0}</p>
            <p className="text-xs text-slate-500 mt-1">Successful Authentication</p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Failed Logins</p>
            <p className="text-3xl font-extrabold text-amber-400 mt-2">{summary?.failed_logons ?? 0}</p>
            <p className="text-xs text-slate-500 mt-1">Authentication Failures</p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Privilege Changes</p>
            <p className="text-3xl font-extrabold text-purple-400 mt-2">{summary?.privilege_changes ?? 0}</p>
            <p className="text-xs text-slate-500 mt-1">Admin & Group Alterations</p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Persistence Events</p>
            <p className="text-3xl font-extrabold text-cyan-400 mt-2">{summary?.persistence_events ?? 0}</p>
            <p className="text-xs text-slate-500 mt-1">Services / Tasks / Run Keys</p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Events</p>
            <p className="text-3xl font-extrabold text-red-500 mt-2">{summary?.critical_events ?? 0}</p>
            <p className="text-xs text-slate-500 mt-1">High Severity & Log Clearing</p>
          </div>
        </div>

        {/* Phase 7: Step-by-Step Attack Sequence Timeline Visualizer */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-white flex items-center space-x-2">
              <span>⏱️ Phase 7 — Attack Chain Sequence Timeline</span>
            </h2>
            <button
              onClick={() => handleSimulate("ATTACK_CHAIN")}
              className="text-xs px-3 py-1 bg-indigo-900/50 hover:bg-indigo-800/70 text-indigo-300 rounded-lg border border-indigo-700/50 transition-all font-semibold"
            >
              Simulate 02:10 ➔ 02:12 Chain
            </button>
          </div>

          {attackChain.length === 0 ? (
            <p className="text-sm text-slate-500 py-4 text-center">No attack sequence chain detected.</p>
          ) : (
            <div className="relative border-l-2 border-slate-800 ml-4 space-y-6 py-2">
              {attackChain.map((item, idx) => (
                <div key={idx} className="relative pl-6 flex items-start justify-between group">
                  {/* Step Connector Node */}
                  <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-slate-900 border-2 border-indigo-500 group-hover:border-cyan-400 transition-colors flex items-center justify-center">
                    <div className="w-1.5 h-1.5 rounded-full bg-indigo-400"></div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-sm font-bold text-cyan-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {item.time}
                      </span>
                      <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${getChainBadgeStyle(item.badge_type)}`}>
                        {item.event_title}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">User: {item.user}</span>
                      <span className="text-xs text-slate-500 font-mono">ID: {item.event_id}</span>
                    </div>
                    <p className="text-xs text-slate-300 font-mono">{item.description}</p>
                  </div>

                  {idx < attackChain.length - 1 && (
                    <div className="hidden md:flex items-center text-slate-600 text-sm font-bold">
                      ↓
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Phase 5 Filters Bar */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200">🔍 Filter Security Events</h3>
            <button onClick={fetchData} className="text-xs text-indigo-400 hover:text-indigo-300 font-medium">
              Apply & Refresh ↻
            </button>
          </div>

          <form onSubmit={handleFilterSubmit} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
            {/* User */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">User</label>
              <input
                type="text"
                placeholder="Filter by user..."
                value={userFilter}
                onChange={(e) => setUserFilter(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* Device */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Device / Hostname</label>
              <input
                type="text"
                placeholder="Filter by device..."
                value={deviceFilter}
                onChange={(e) => setDeviceFilter(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* Severity */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Severity</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Severities</option>
                <option value="Information">Information</option>
                <option value="Warning">Warning</option>
                <option value="Error">Error</option>
                <option value="Critical">Critical</option>
              </select>
            </div>

            {/* Event Type */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Event Type</label>
              <select
                value={eventTypeFilter}
                onChange={(e) => setEventTypeFilter(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Event Types</option>
                <option value="AUTHENTICATION_SUCCESS">Auth Success</option>
                <option value="AUTHENTICATION_FAILURE">Auth Failure</option>
                <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
                <option value="ACCOUNT_MANAGEMENT">Account Management</option>
                <option value="DEFENSE_EVASION">Defense Evasion</option>
                <option value="PERSISTENCE">Persistence</option>
                <option value="SYSTEM_EVENT">System Event</option>
              </select>
            </div>

            {/* Date */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Date</label>
              <select
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Time</option>
                <option value="today">Today</option>
                <option value="last_24h">Last 24 Hours</option>
                <option value="last_7d">Last 7 Days</option>
              </select>
            </div>

            {/* Keyword Search */}
            <div>
              <label className="block text-xs font-semibold text-slate-400 mb-1">Keyword</label>
              <input
                type="text"
                placeholder="Search description..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </form>
        </div>

        {/* Security Events Stream Table */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200">Security Events Stream ({events.length})</h3>
            <span className="text-xs text-slate-400">Phase 6 Response Engine Ready</span>
          </div>

          {loading ? (
            <div className="p-12 text-center text-slate-500">Loading Security Events...</div>
          ) : error ? (
            <div className="p-6 text-center text-red-400">{error}</div>
          ) : events.length === 0 ? (
            <div className="p-12 text-center text-slate-500">No Security Events found matching current filters.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-950 text-xs uppercase text-slate-400 font-mono border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Time</th>
                    <th className="py-3 px-4">User</th>
                    <th className="py-3 px-4">Device</th>
                    <th className="py-3 px-4">Event</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Source</th>
                    <th className="py-3 px-4">Phase 6 Response Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                  {events.map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap">{new Date(evt.timestamp).toLocaleString()}</td>
                      <td className="py-3 px-4 text-indigo-300 font-semibold">{evt.username || "SYSTEM"}</td>
                      <td className="py-3 px-4 text-slate-300">{evt.computer || "Endpoint"}</td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-200">{evt.event_type} (ID: {evt.event_id})</div>
                        <div className="text-slate-400 text-[11px] truncate max-w-sm">{evt.description}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${getSeverityBadgeClass(evt.level)}`}>
                          {evt.level}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-semibold">{evt.event_source}</td>

                      {/* Phase 6 Quick Actions */}
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-1.5">
                          <button
                            onClick={() => setSelectedEvent(evt)}
                            className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs"
                          >
                            Details
                          </button>
                          <button
                            disabled={actionExecuting}
                            onClick={() => handleResponseAction("DISABLE_USER", evt)}
                            title="Disable User (Simulation)"
                            className="px-2 py-1 bg-red-950/60 hover:bg-red-900/80 text-red-400 rounded border border-red-800/60 text-xs font-semibold"
                          >
                            Disable
                          </button>
                          <button
                            disabled={actionExecuting}
                            onClick={() => handleResponseAction("FORCE_LOGOUT", evt)}
                            title="Force Logout Session (Simulation)"
                            className="px-2 py-1 bg-amber-950/60 hover:bg-amber-900/80 text-amber-400 rounded border border-amber-800/60 text-xs font-semibold"
                          >
                            Logoff
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>

      {/* Event Details & Response Action Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white">Event Details & Response Control</h3>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <div className="space-y-2 text-sm font-mono text-slate-300">
              <p><strong className="text-slate-400">Description:</strong> {selectedEvent.description}</p>
              <p><strong className="text-slate-400">Source:</strong> {selectedEvent.event_source} (ID: {selectedEvent.event_id})</p>
              <p><strong className="text-slate-400">User:</strong> {selectedEvent.username} ({selectedEvent.domain || "Local"})</p>
              <p><strong className="text-slate-400">Device:</strong> {selectedEvent.computer}</p>
              <p><strong className="text-slate-400">IP Address:</strong> {selectedEvent.ip_address || "Local"}</p>
              <div>
                <strong className="text-slate-400">Raw JSON Payload:</strong>
                <pre className="mt-2 bg-slate-950 p-3 rounded-lg text-xs overflow-x-auto text-emerald-400 border border-slate-800 max-h-40">
                  {JSON.stringify(selectedEvent.raw_event || selectedEvent, null, 2)}
                </pre>
              </div>
            </div>

            {/* Phase 6 Audited Response Action Controls */}
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <span className="block text-xs font-semibold text-slate-400 uppercase tracking-wider">Execute Audited Response Action</span>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                <button
                  disabled={actionExecuting}
                  onClick={() => handleResponseAction("DISABLE_USER", selectedEvent)}
                  className="px-3 py-2 bg-red-900/50 hover:bg-red-800/80 text-red-300 rounded-lg text-xs font-bold border border-red-700/50 transition-colors"
                >
                  Disable User
                </button>
                <button
                  disabled={actionExecuting}
                  onClick={() => handleResponseAction("FORCE_LOGOUT", selectedEvent)}
                  className="px-3 py-2 bg-amber-900/50 hover:bg-amber-800/80 text-amber-300 rounded-lg text-xs font-bold border border-amber-700/50 transition-colors"
                >
                  Force Logout
                </button>
                <button
                  disabled={actionExecuting}
                  onClick={() => handleResponseAction("INVESTIGATE", selectedEvent)}
                  className="px-3 py-2 bg-blue-900/50 hover:bg-blue-800/80 text-blue-300 rounded-lg text-xs font-bold border border-blue-700/50 transition-colors"
                >
                  Investigate
                </button>
                <button
                  disabled={actionExecuting}
                  onClick={() => handleResponseAction("IGNORE", selectedEvent)}
                  className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-bold border border-slate-700 transition-colors"
                >
                  Ignore
                </button>
                <button
                  disabled={actionExecuting}
                  onClick={() => handleResponseAction("ALLOWLIST", selectedEvent)}
                  className="px-3 py-2 bg-emerald-900/50 hover:bg-emerald-800/80 text-emerald-300 rounded-lg text-xs font-bold border border-emerald-700/50 transition-colors"
                >
                  Allowlist
                </button>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button onClick={() => setSelectedEvent(null)} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Simulate Attack Modal */}
      {showSimulateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                <span>⚡ Trigger Attack Simulation</span>
              </h3>
              <button onClick={() => setShowSimulateModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <p className="text-xs text-slate-400">
              Fire test OS security event sequences to trigger detection rules, threat scoring, and live UI telemetry.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <button
                disabled={simulating}
                onClick={() => handleSimulate("ATTACK_CHAIN")}
                className="p-3 bg-gradient-to-r from-indigo-950 to-purple-950 hover:from-indigo-900 hover:to-purple-900 border border-indigo-500/50 rounded-xl text-left transition-all col-span-2 shadow-lg"
              >
                <div className="text-sm font-bold text-indigo-300">⚡ Phase 7: Full 02:10 ➔ 02:12 Attack Chain</div>
                <div className="text-xs text-slate-300 mt-1">Failed Login (02:10) ➔ Failed Login (02:10) ➔ Admin Login (02:11) ➔ New Scheduled Task (02:12) ➔ Critical Alert</div>
              </button>

              <button
                disabled={simulating}
                onClick={() => handleSimulate("BRUTE_FORCE")}
                className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-red-500/50 rounded-xl text-left transition-all"
              >
                <div className="text-sm font-bold text-red-400">1. Brute Force Attack</div>
                <div className="text-xs text-slate-400 mt-1">5 rapid failed logons (RDP/SSH) from external IP</div>
              </button>

              <button
                disabled={simulating}
                onClick={() => handleSimulate("PRIVILEGE_ESCALATION")}
                className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-amber-500/50 rounded-xl text-left transition-all"
              >
                <div className="text-sm font-bold text-amber-400">2. Admin Escalation</div>
                <div className="text-xs text-slate-400 mt-1">User added to Administrators / sudo group</div>
              </button>

              <button
                disabled={simulating}
                onClick={() => handleSimulate("ACCOUNT_DISABLED")}
                className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-indigo-500/50 rounded-xl text-left transition-all"
              >
                <div className="text-sm font-bold text-indigo-400">3. Account Disabled</div>
                <div className="text-xs text-slate-400 mt-1">User account lockout / disable event</div>
              </button>

              <button
                disabled={simulating}
                onClick={() => handleSimulate("OFF_HOURS")}
                className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-purple-500/50 rounded-xl text-left transition-all"
              >
                <div className="text-sm font-bold text-purple-400">4. Off-Hours Logon</div>
                <div className="text-xs text-slate-400 mt-1">Interactive logon at 03:15 AM</div>
              </button>

              <button
                disabled={simulating}
                onClick={() => handleSimulate("PERSISTENCE")}
                className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/50 rounded-xl text-left transition-all"
              >
                <div className="text-sm font-bold text-cyan-400">5. Service Persistence</div>
                <div className="text-xs text-slate-400 mt-1">Windows service creation event</div>
              </button>

              <button
                disabled={simulating}
                onClick={() => handleSimulate("LOG_CLEARING")}
                className="p-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-red-600 rounded-xl text-left transition-all font-semibold"
              >
                <div className="text-sm font-bold text-red-500">6. Security Log Cleared</div>
                <div className="text-xs text-slate-400 mt-1">CRITICAL anti-forensics log wipe event</div>
              </button>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button onClick={() => setShowSimulateModal(false)} className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
