import { useEffect, useMemo, useState } from "react";
import { fetchPlugins } from "../api";
import { getState, setState } from "../api";

export default function Settings() {
  const [plugins, setPlugins] = useState<string[]>([]);
  const [traitsInput, setTraitsInput] = useState<string>("");
  const [disabled, setDisabled] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string>("");

  useEffect(() => {
    (async () => {
      const [pl, st] = await Promise.all([fetchPlugins(), getState()]);
      setPlugins(pl);
      setTraitsInput(st.traits.join(", "));
      setDisabled(new Set(st.disabled));
    })().catch((e) => setMsg(String(e)));
  }, []);

  const sortedPlugins = useMemo(() => [...new Set([...plugins, ...disabled])].sort(), [plugins, disabled]);

  async function save() {
    setSaving(true); setMsg("");
    try {
      const traits = traitsInput.split(",").map(s => s.trim()).filter(Boolean);
      await setState({ traits, disabled: Array.from(disabled) });
      setMsg("Saved.");
    } catch (e:any) {
      setMsg(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-semibold">Settings</h1>

      <section className="rounded-2xl border border-slate-800 p-4 space-y-3">
        <div className="text-sm text-slate-400">Traits (comma-separated)</div>
        <input
          className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-sm outline-none w-full"
          placeholder="e.g., demo, admin"
          value={traitsInput}
          onChange={(e) => setTraitsInput(e.target.value)}
        />
        <div className="text-xs text-slate-400">These act like feature flags / capabilities required by some plugins.</div>
      </section>

      <section className="rounded-2xl border border-slate-800 p-4 space-y-3">
        <div className="text-sm text-slate-400">Plugins</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {sortedPlugins.map((p) => {
            const isDisabled = disabled.has(p);
            return (
              <label key={p} className="flex items-center gap-3 rounded-xl px-3 py-2 bg-slate-900 border border-slate-800">
                <input
                  type="checkbox"
                  className="h-4 w-4"
                  checked={!isDisabled}
                  onChange={(e) => {
                    const next = new Set(disabled);
                    if (e.target.checked) next.delete(p); else next.add(p);
                    setDisabled(next);
                  }}
                />
                <span className="text-sm">{p}</span>
                <span className={`ml-auto text-xs ${isDisabled ? "text-red-400" : "text-emerald-400"}`}>
                  {isDisabled ? "disabled" : "enabled"}
                </span>
              </label>
            );
          })}
          {sortedPlugins.length === 0 && <div className="text-slate-400 text-sm">No plugins detected yet.</div>}
        </div>
      </section>

      <div className="flex items-center gap-3">
        <button
          className="rounded-xl bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-sm disabled:opacity-60"
          onClick={save}
          disabled={saving}
        >
          {saving ? "Saving…" : "Save"}
        </button>
        <div className="text-xs text-slate-400">{msg}</div>
      </div>
    </div>
  );
}
