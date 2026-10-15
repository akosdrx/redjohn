import { lazy, Suspense, useEffect, useState } from "react";
import { strings, EmptyState, ErrorState, LoadingState } from "@redjohn/ui";
import { useEngine } from "./lib/engine";
import { bridge } from "./bridge";
import { Sidebar, type NavPage } from "./components/Sidebar";
import type { SessionTab } from "./pages/PentestSession";
import { SETTINGS_SECTIONS, type SettingsSection } from "./pages/settingsSections";
import { useUiStore } from "./store/ui";
import { MemoryReadyGate } from "./components/MemoryReadyGate";
import { ErrorBoundary } from "./components/ErrorBoundary";

const PentestSession = lazy(() => import("./pages/PentestSession").then(({ PentestSession }) => ({ default: PentestSession })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then(({ SettingsPage }) => ({ default: SettingsPage })));

export function App() {
  const { info, api } = useEngine();
  const [page, setPage] = useState<NavPage>("pentests");
  const [tab, setTab] = useState<SessionTab>("workspace");
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("providers");
  const runId = useUiStore((state) => state.selectedRunId);
  useEffect(() => {
    const handler = (event: Event): void => {
      const detail = (event as CustomEvent<string | { page: string; section?: string }>).detail;
      const target = typeof detail === "string" ? detail : detail?.page;
      if (["workspace", "findings", "artifacts", "reports"].includes(target)) { setTab(target as SessionTab); setPage("pentests"); }
      else if (target === "settings") {
        if (typeof detail === "object" && SETTINGS_SECTIONS.some((section) => section.id === detail.section)) setSettingsSection(detail.section as SettingsSection);
        setPage("settings");
      }
    };
    window.addEventListener("redjohn:navigate", handler);
    return () => window.removeEventListener("redjohn:navigate", handler);
  }, []);
  return <div className="rj-root flex h-screen flex-col overflow-hidden">
    {bridge.platform === "darwin" && <div aria-hidden="true" className="rj-titlebar h-10 shrink-0 border-b border-rj-border bg-rj-sidebar" />}
    {info.state === "starting" ? <div className="flex flex-1 items-center justify-center"><LoadingState label="Starting the RedJohn engine…" /></div> : info.state !== "running" || !api ?
      <div className="flex flex-1 items-center justify-center"><ErrorState title={strings.states.engineDownTitle} detail={info.detail ?? strings.states.engineDownDetail} onRetry={() => { void bridge.restartEngine().catch(() => window.location.reload()); }} /></div> :
      <MemoryReadyGate><div className="flex min-h-0 flex-1"><Sidebar page={page} onNavigate={(next) => { setPage(next); if (next === "pentests") setTab("workspace"); }} />
        <main className="flex min-h-0 min-w-0 flex-1 flex-col"><ErrorBoundary key={`${page}:${runId ?? ""}:${settingsSection}`}><Suspense fallback={<LoadingState />}>{page === "pentests" ? runId ? <PentestSession key={runId} tab={tab} onTabChange={setTab} /> : <div className="flex flex-1 items-center justify-center"><EmptyState title="Select a pentest or create a new one." /></div> : <SettingsPage key={settingsSection} initialSection={settingsSection} />}</Suspense></ErrorBoundary></main>
      </div></MemoryReadyGate>}
  </div>;
}
