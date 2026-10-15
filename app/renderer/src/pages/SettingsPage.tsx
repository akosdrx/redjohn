import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button, ErrorState, LoadingState, Panel, StatusPill, strings } from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import { SkillsBrowser } from "./SkillsBrowser";
import { ProvidersSettings } from "./ProvidersSettings";
import { MemorySettings } from "./MemorySettings";
import { bridge } from "../bridge";
import { NvdSettings } from "./NvdSettings";
import { ToolsSettings } from "./ToolsSettings";
import { SETTINGS_SECTIONS, type SettingsSection } from "./settingsSections";
export { SETTINGS_SECTIONS, type SettingsSection } from "./settingsSections";

export function SettingsPage({ initialSection = "providers" }: { initialSection?: SettingsSection }) {
  const [section, setSection] = useState(initialSection);
  return <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
    <h1 className="text-[15px] font-semibold text-rj-text">{strings.settings.title}</h1>
    <nav aria-label="Settings sections" className="flex flex-wrap gap-1 border-b border-rj-border pb-2">
      {SETTINGS_SECTIONS.map((tab) => <Button key={tab.id} variant={section === tab.id ? "outline" : "ghost"} aria-current={section === tab.id ? "page" : undefined} onClick={() => setSection(tab.id)}>{tab.label}</Button>)}
    </nav>
    {section === "providers" && <ProvidersSettings />}
    {section === "memory" && <MemorySettings />}
    {section === "tools" && <ToolsSettings />}
    {section === "skills" && <SkillsBrowser />}
    {section === "nvd" && <NvdSettings />}
    {import.meta.env.DEV && section === "engine" && <EngineSettings />}
  </div>;
}

function EngineSettings() {
  const { api, info } = useEngine();
  const [restartError, setRestartError] = useState("");
  const [restarting, setRestarting] = useState(false);
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api!.getSettings(), enabled: !!api });
  return <Panel title={strings.settings.engineSection} padded>
    <div className="mb-3 flex flex-wrap items-center gap-3">
      <StatusPill kind="service" state={info.state === "running" ? "live" : info.state === "failed" ? "down" : "starting"} label={`${strings.settings.engineStatus}: ${info.state}`} />
      <span className="break-all font-mono text-[11px] text-rj-text-3">{info.baseUrl ?? "—"}</span>
      <Button variant="outline" size="sm" disabled={restarting} onClick={async () => { setRestarting(true); setRestartError(""); try { await bridge.restartEngine(); } catch (e) { setRestartError(String(e)); } finally { setRestarting(false); } }}>{restarting ? "Restarting…" : strings.settings.restartEngine}</Button>
      <Button variant="outline" size="sm" onClick={() => void bridge.openLogs()}>{strings.terminal.openLogs}</Button>
    </div>
    {info.detail && <p className="mb-3 text-[12px] text-rj-text-3">{info.detail}</p>}
    {restartError && <ErrorState detail={restartError} />}
    {settings.isPending ? <LoadingState /> : settings.isError ? <ErrorState detail={String(settings.error)} /> : <p className="text-[12px] text-rj-text-2">Profile: {settings.data.data_profile} · {info.profileDir}</p>}
  </Panel>;
}
