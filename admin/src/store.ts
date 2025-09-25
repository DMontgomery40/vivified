import { create } from "zustand";
import { fetchPlugins, health } from "./api";

type State = {
  apiHealthy: boolean;
  plugins: string[];
  loading: boolean;
  error: string | null;
  loadAll: () => Promise<void>;
};

export const useApp = create<State>((set) => ({
  apiHealthy: false,
  plugins: [],
  loading: false,
  error: null,
  loadAll: async () => {
    set({ loading: true, error: null });
    try {
      const [ok, plugins] = await Promise.all([health(), fetchPlugins()]);
      set({ apiHealthy: ok, plugins, loading: false });
    } catch (e: any) {
      set({ error: String(e), loading: false });
    }
  },
}));

