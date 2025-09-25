import { useEffect, useState } from "react";
import { fetchPlugins, runPlugin } from "../api";

export default function Plugins() {
  const [list, setList] = useState<string[]>([]);
  const [arg0, setArg0] = useState<string>("Vivi");
  const [out, setOut] = useState<string>("");

  useEffect(() => { fetchPlugins().then(setList).catch(() => setList([])); }, []);

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-semibold">Plugins</h1>
      <div className="rounded-2xl border border-slate-800 p-4 space-y-3">
        <div className="text-sm text-slate-400">Available</div>
        <div className="flex flex-wrap gap-2">
          {list.map((p) => (
            <span key={p} className="px-2 py-1 rounded-lg bg-slate-800 text-xs">{p}</span>
          ))}
          {list.length === 0 && <span className="text-slate-400 text-sm">No plugins found.</span>}
        </div>
        <div className="h-px bg-slate-800 my-2" />
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!list[0]) { setOut("No plugins to run."); return; }
            try {
              const code = await runPlugin(list[0], [arg0]);
              setOut(`Exit code: ${code}`);
            } catch (err: any) {
              setOut(String(err));
            }
          }}
          className="flex items-center gap-2"
        >
          <input
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-sm outline-none w-60"
            placeholder="Arg for plugin[0] (hello)"
            value={arg0}
            onChange={(e) => setArg0(e.target.value)}
          />
          <button
            className="rounded-xl bg-emerald-600 hover:bg-emerald-500 px-3 py-2 text-sm"
            type="submit"
          >
            Run first plugin
          </button>
        </form>
        <div className="text-xs text-slate-400 break-words">{out}</div>
      </div>
    </div>
  );
}

