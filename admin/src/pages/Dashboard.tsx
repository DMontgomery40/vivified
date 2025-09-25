import { useEffect } from "react";
import { useApp } from "../store";

export default function Dashboard() {
  const { apiHealthy, plugins, loading, error, loadAll } = useApp();
  useEffect(() => { loadAll(); }, [loadAll]);
  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      {loading && <div>Loading…</div>}
      {error && <div className="text-red-400">{error}</div>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-slate-800 p-4">
          <div className="text-sm text-slate-400 mb-1">API Health</div>
          <div className={`text-lg ${apiHealthy ? "text-emerald-400" : "text-red-400"}`}>
            {apiHealthy ? "Healthy" : "Unreachable"}
          </div>
        </div>
        <div className="rounded-2xl border border-slate-800 p-4">
          <div className="text-sm text-slate-400 mb-1">Plugins Detected</div>
          <div className="text-lg">{plugins.length}</div>
          <div className="text-xs text-slate-400 mt-2 break-words">{plugins.join(", ") || "—"}</div>
        </div>
      </div>
    </div>
  );
}

