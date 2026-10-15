// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProvidersSettings } from "./ProvidersSettings";
import { MemorySettings } from "./MemorySettings";
import { SettingsPage } from "./SettingsPage";
import { NewPentestDialog } from "@redjohn/ui";

const mock = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>> }));
vi.mock("../lib/engine", () => ({ useEngine: () => ({ api: mock.api, info: { state: "running", baseUrl: "http://127.0.0.1:8720/api/v1", profileDir: "/profile" } }) }));
const clients: QueryClient[] = [];
function mount(element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  return render(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
}
afterEach(() => { cleanup(); clients.splice(0).forEach((client) => client.clear()); });
const memory = { openviking_url: "", openviking_account: "redjohn", openviking_user: "local-user", openviking_processing_mode: "vectors_only", service_key_configured: false, server_models: {}, generated_config: null, model_config_applied: false, configured: false, mode: "provider", language_model: "", local_models_installed: false };
beforeEach(() => {
  mock.api = {
    getProviderCatalog: vi.fn().mockResolvedValue({ providers: [
      { id: "zai", name: "Z.ai API", base_url: "https://api.z.ai/api/paas/v4", default_model: "glm-4.7", models: [{ id: "glm-4.7", name: "GLM 4.7" }] },
      { id: "zai-coding-plan", name: "Z.ai Coding Plan", base_url: "https://api.z.ai/api/coding/paas/v4", default_model: "glm-4.7", models: [{ id: "glm-4.7", name: "GLM 4.7" }] },
      { id: "codex", name: "Codex · ChatGPT subscription", base_url: "", default_model: "", models: [] },
    ] }),
    listProviders: vi.fn().mockResolvedValue({ items: [], active_provider: null, runtime_provider: "anthropic", runtime_model: "claude-sonnet-4-5" }),
    saveProvider: vi.fn().mockResolvedValue({ id: "provider-1" }),
    getCodexStatus: vi.fn().mockResolvedValue({ available: true, authenticated: false, models: [], login: null }),
    startCodexLogin: vi.fn().mockResolvedValue({ loginId: "login", verificationUrl: "https://auth.openai.com/codex/device", userCode: "ABCD-1234", state: "pending" }),
    listNativeTools: vi.fn().mockResolvedValue({ items: [{ id: "nuclei", name: "Nuclei", available: true, origin: "system", downloadable: true }] }),
    listSkills: vi.fn().mockResolvedValue({ items: [{ skill_id: "skl_1", name: "00-master-pentest-methodology", description: "Master methodology" }], total: 28 }),
    getMemoryConfig: vi.fn().mockResolvedValue(memory),
    getStatus: vi.fn().mockResolvedValue({ services: [{ service: "openviking", state: "not_configured", detail: "Choose a memory mode." }] }),
    setupMemory: vi.fn().mockResolvedValue(memory),
    saveMemoryConfig: vi.fn().mockResolvedValue(memory),
    generateMemoryConfig: vi.fn().mockResolvedValue({ ...memory, generated_config: "/profile/openviking/ov.conf" }),
    startLocalMemory: vi.fn().mockResolvedValue({ ...memory, openviking_url: "http://127.0.0.1:1942", openviking_processing_mode: "", service_key_configured: true, model_config_applied: true }),
  };
});

describe("usable integration settings", () => {
  it("uses the separate Coding Plan endpoint and clears the write-only key after saving", async () => {
    mount(<ProvidersSettings />);
    fireEvent.click(await screen.findByRole("button", { name: "Add provider connection" }));
    fireEvent.click(screen.getByRole("button", { name: /Z.ai Coding Plan/ }));
    fireEvent.change(screen.getByLabelText("Provider API key"), { target: { value: "private-test" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    fireEvent.click(await screen.findByRole("button", { name: "Save connection" }));
    await waitFor(() => expect(mock.api.saveProvider).toHaveBeenCalledWith(expect.objectContaining({ provider: "zai-coding-plan", base_url: "https://api.z.ai/api/coding/paas/v4", api_key: "private-test" })));
    await screen.findByText(/Provider connection saved/);
    expect(screen.queryByLabelText("Provider API key")).not.toBeInTheDocument();
  });
  it("offers subscription sign-in without an API-key input", async () => {
    mount(<ProvidersSettings />);
    fireEvent.click(await screen.findByRole("button", { name: "Add provider connection" }));
    fireEvent.click(screen.getByRole("button", { name: /Codex · ChatGPT subscription/ }));
    expect(screen.queryByLabelText("Provider API key")).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Sign in with Codex" }));
    mock.api.getCodexStatus!.mockResolvedValue({ available: true, authenticated: false, models: [], login: { loginId: "login", verificationUrl: "https://auth.openai.com/codex/device", userCode: "ABCD-1234", state: "pending" } });
    expect(await screen.findByText("ABCD-1234")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "the sign-in page" })).toHaveAttribute("href", "https://auth.openai.com/codex/device");
  });
  it("lists Tools and Skills in Settings without any MCP section", async () => {
    mount(<SettingsPage initialSection="tools" />);
    expect(await screen.findByText("Nuclei")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /MCP/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Skills" }));
    expect(await screen.findByText("00-master-pentest-methodology")).toBeInTheDocument();
  });
  it("opens Memory without any setup call and shows the external embedding fields", async () => {
    mount(<MemorySettings />);
    await screen.findByLabelText("Embeddings base URL");
    expect(mock.api.setupMemory).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Embeddings model")).toBeInTheDocument();
    expect(screen.getByLabelText("Embeddings dimension")).toBeInTheDocument();
    // No local-model runtime: no "Install Qwen" / mode selector anymore.
    expect(screen.queryByRole("button", { name: "Install Qwen" })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Memory mode" })).not.toBeInTheDocument();
  });
  it("saves memory with the provider language model and an external embeddings endpoint", async () => {
    mock.api.listProviders!.mockResolvedValue({ items: [{ id: "provider1", label: "Z.ai", provider: "zai", model: "glm-4.7", auth_method: "api_key" }] });
    mount(<MemorySettings />);
    fireEvent.click(await screen.findByRole("combobox", { name: "Memory provider" }));
    fireEvent.click(screen.getByRole("option", { name: "Z.ai · GLM 4.7" }));
    expect(screen.getByRole("combobox", { name: "Memory model" })).toHaveTextContent("GLM 4.7");
    fireEvent.change(screen.getByLabelText("Embeddings base URL"), { target: { value: "https://api.openai.com/v1" } });
    fireEvent.change(screen.getByLabelText("Embeddings model"), { target: { value: "text-embedding-3-small" } });
    fireEvent.change(screen.getByLabelText("Embeddings API key"), { target: { value: "embed-private" } });
    fireEvent.click(screen.getByRole("button", { name: "Save memory configuration" }));
    await waitFor(() => expect(mock.api.setupMemory).toHaveBeenCalledWith({
      provider_connection_id: "provider1",
      model: "glm-4.7",
      embedding_base_url: "https://api.openai.com/v1",
      embedding_model: "text-embedding-3-small",
      embedding_dimension: 1536,
      embedding_api_key: "embed-private",
    }));
    expect(screen.queryByLabelText("Provider API key")).not.toBeInTheDocument();
  });
  it("creates a session without project, environment, tool-policy or agent-limit fields", async () => {
    const submit = vi.fn().mockResolvedValue(undefined);
    mount(<NewPentestDialog open onClose={() => {}} onSubmit={submit} />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Web review" } });
    fireEvent.change(screen.getByLabelText("Authorized target"), { target: { value: "https://example.com" } });
    expect(screen.queryByText("Project")).not.toBeInTheDocument();
    expect(screen.queryByText("Environment")).not.toBeInTheDocument();
    expect(screen.queryByText(/Allowed tools|Max agents|Max concurrent|delegation depth/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("combobox", { name: "Scan mode" }));
    expect(screen.getAllByRole("option").map((option) => option.textContent?.replace("✓", ""))).toEqual(["Low", "Standard", "High", "Deep"]);
    fireEvent.click(screen.getByRole("option", { name: "Deep" }));
    fireEvent.click(screen.getByRole("button", { name: "Create pentest" }));
    await waitFor(() => expect(submit).toHaveBeenCalledWith({ name: "Web review", authorizedTarget: "https://example.com", targetKind: "web_application", scanMode: "deep", task: "" }));
  });
  it("allows saving a local embeddings endpoint without an API key and blocks non-positive dimensions", async () => {
    mock.api.listProviders!.mockResolvedValue({ items: [{ id: "provider1", label: "Z.ai", provider: "zai", model: "glm-4.7", auth_method: "api_key" }] });
    mount(<MemorySettings />);
    fireEvent.click(await screen.findByRole("combobox", { name: "Memory provider" }));
    fireEvent.click(screen.getByRole("option", { name: "Z.ai · GLM 4.7" }));
    fireEvent.change(screen.getByLabelText("Embeddings base URL"), { target: { value: "http://127.0.0.1:11434/v1" } });
    fireEvent.change(screen.getByLabelText("Embeddings model"), { target: { value: "nomic-embed-text" } });
    fireEvent.change(screen.getByLabelText("Embeddings dimension"), { target: { value: "0" } });
    expect(screen.getByRole("button", { name: "Save memory configuration" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Embeddings dimension"), { target: { value: "768" } });
    expect(screen.getByRole("button", { name: "Save memory configuration" })).not.toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Save memory configuration" }));
    await waitFor(() => expect(mock.api.setupMemory).toHaveBeenCalledWith({
      provider_connection_id: "provider1",
      model: "glm-4.7",
      embedding_base_url: "http://127.0.0.1:11434/v1",
      embedding_model: "nomic-embed-text",
      embedding_dimension: 768,
    }));
  });
});
