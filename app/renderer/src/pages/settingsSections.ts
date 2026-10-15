export type SettingsSection = "providers" | "memory" | "tools" | "engine" | "skills" | "nvd";
export const SETTINGS_SECTIONS: Array<{ id: SettingsSection; label: string }> = [
  { id: "providers", label: "Providers" }, { id: "memory", label: "Memory" },
  { id: "tools", label: "Tools" }, { id: "skills", label: "Skills" },
  { id: "nvd", label: "NIST NVD" },
  ...(import.meta.env.DEV ? [{ id: "engine" as const, label: "Engine debug" }] : []),
];
