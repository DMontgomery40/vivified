import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";
import Dashboard from "./pages/Dashboard";
import Diagnostics from "./pages/Diagnostics";
import Plugins from "./pages/Plugins";
import Settings from "./pages/Settings";
import { Nav } from "./components/Nav";

function Shell() {
  return (
    <div className="flex">
      <Nav />
      <main className="flex-1 min-h-screen bg-slate-950">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/diagnostics" element={<Diagnostics />} />
          <Route path="/plugins" element={<Plugins />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  </React.StrictMode>
);
