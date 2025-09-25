import { Activity, Puzzle, Settings, LayoutDashboard } from "lucide-react";
import { Link, useLocation } from "react-router-dom";

const items = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/diagnostics", label: "Diagnostics", icon: Activity },
  { to: "/plugins", label: "Plugins", icon: Puzzle },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Nav() {
  const { pathname } = useLocation();
  return (
    <nav className="w-60 min-h-screen bg-slate-900 border-r border-slate-800 p-4">
      <div className="text-2xl font-semibold tracking-tight mb-6">Vivi</div>
      <ul className="space-y-1">
        {items.map(({ to, label, icon: Icon }) => {
          const active = pathname === to || (to !== "/" && pathname.startsWith(to));
          return (
            <li key={to}>
              <Link
                to={to}
                className={`flex items-center gap-3 rounded-xl px-3 py-2 hover:bg-slate-800 ${active ? "bg-slate-800" : ""}`}
              >
                <Icon className="h-4 w-4" />
                <span className="text-sm">{label}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

