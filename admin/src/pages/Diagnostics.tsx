import { useEffect, useState } from "react";
import { health } from "../api";

export default function Diagnostics() {
  const [ok, setOk] = useState<boolean | null>(null);
  const [ts, setTs] = useState<number>(0);
  useEffect(() => {
    const f = async () => { setOk(await health()); setTs(Date.now()); };
    f();
  }, []);
  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-semibold">Diagnostics</h1>
      <div className="rounded-2xl border border-slate-800 p-4">
        <div className="text-sm text-slate-400 mb-1">/health</div>
        <div className={`text-lg ${ok ? "text-emerald-400" : "text-red-400"}`}>
          {ok === null ? "…" : ok ? "OK" : "Not OK"}
        </div>
        <div className="text-xs text-slate-400 mt-2">Checked: {ts ? new Date(ts).toLocaleString() : "—"}</div>
      </div>
    </div>
  );
}

