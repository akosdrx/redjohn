/**
 * Typed REST client for the RedJohn engine API.
 * Types come from the generated contract (./schema.d.ts — do not hand-edit).
 * The token is supplied by the secure IPC bridge, never hardcoded or stored
 * in localStorage.
 */
import type { components } from "./schema";
import type { components as IntegrationComponents } from "./integrations-schema";

export type Schemas = components["schemas"];
export type Run = Schemas["Run"];
export type Agent = Schemas["Agent"];
export type Finding = Schemas["Finding"];
export type Target = Schemas["Target"];
export type Project = Schemas["Project"];
export type Workspace = Schemas["Workspace"];
export type ScopePolicy = Schemas["ScopePolicy"];
export type AgentLimits = Schemas["AgentLimits"];
export type AgentMessage = Schemas["AgentMessage"];
export type SkillRef = Schemas["SkillRef"];
export type ServiceStatus = Schemas["ServiceStatus"];
export type Settings = Schemas["Settings"];
export type Report = Schemas["Report"];
export type Evidence = Schemas["Evidence"];
export type RunEvent = Schemas["RunEvent"];
export type RunStatus = Schemas["RunStatus"];
export type FindingSeverity = Schemas["FindingSeverity"];
export type FindingStatus = Schemas["FindingStatus"];
export type TargetKind = Schemas["TargetKind"];

export interface ListPage<T> {
  items: T[];
  next_cursor?: string | null;
  total?: number | null;
}

export interface StatusResponse {
  services: ServiceStatus[];
  contract_version: string;
  engine_version?: string;
}

export interface Capabilities {
  environment?: Schemas["RunEnvironment"];
  limits?: AgentLimits;
  openviking?: boolean;
  pty?: boolean;
  reports?: Array<"html" | "json" | "pdf">;
}

export interface RunSnapshot {
  run: Run;
  agents: Agent[];
  findings?: Finding[];
  services?: ServiceStatus[];
  cursor: number;
}

type IntegrationSchemas = IntegrationComponents["schemas"];
export type ProviderConnection = IntegrationSchemas["ProviderConnectionDTO"];
export type ProviderCatalog = IntegrationSchemas["ProviderCatalogDTO"];
export type MemoryConfig = IntegrationSchemas["MemoryConfigDTO"];
export type CodexLogin = IntegrationSchemas["CodexLoginDTO"];
export type CodexStatus = IntegrationSchemas["CodexStatusDTO"];

export interface ApiClientConfig {
  /** e.g. http://127.0.0.1:8720/api/v1 — loopback only. */
  baseUrl: string;
  getToken: () => string | null | Promise<string | null>;
  fetchFn?: typeof fetch;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: Record<string, unknown>,
    public requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ErrorBody {
  error?: { code?: string; message?: string; details?: Record<string, unknown>; request_id?: string };
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export function createApiClient(cfg: ApiClientConfig) {
  const fetchFn = cfg.fetchFn ?? fetch;

  async function request<T>(
    method: string,
    path: string,
    opts: { query?: Record<string, string | number | boolean | undefined>; body?: unknown; idempotencyKey?: string } = {},
  ): Promise<T> {
    const token = await cfg.getToken();
    const url = new URL(`${cfg.baseUrl}${path}`);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = { Accept: "application/json" };
    // Token travels in the Authorization header — never in the URL.
    if (token) headers.Authorization = `Bearer ${token}`;
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;

    const res = await fetchFn(url.toString(), {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : null,
      signal: AbortSignal.timeout(60_000),
    });

    if (res.status === 204) return undefined as T;
    const text = await res.text();
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        /* non-JSON body */
      }
    }
    if (!res.ok) {
      const errBody = (json ?? {}) as ErrorBody;
      throw new ApiError(
        res.status,
        errBody.error?.code ?? `http_${res.status}`,
        errBody.error?.message ?? res.statusText,
        errBody.error?.details,
        errBody.error?.request_id,
      );
    }
    return json as T;
  }

  return {
    /** Loopback base URL this client talks to (e.g. for deriving the WS URL). */
    baseUrl: cfg.baseUrl,

    // meta
    getStatus: () => request<StatusResponse>("GET", "/status"),
    getCapabilities: () => request<Capabilities>("GET", "/capabilities"),

    // projects
    listProjects: (q: { cursor?: string; limit?: number } = {}) =>
      request<ListPage<Project>>("GET", "/projects", { query: q }),
    createProject: (name: string, description?: string) =>
      request<Project>("POST", "/projects", { body: { name, description }, idempotencyKey: newIdempotencyKey() }),
    getProject: (projectId: string) =>
      request<{ project: Project; targets?: Target[]; scope?: ScopePolicy }>("GET", `/projects/${enc(projectId)}`),
    addTarget: (projectId: string, input: { value: string; kind: TargetKind; note?: string }) =>
      request<Target>("POST", `/projects/${enc(projectId)}/targets`, { body: input, idempotencyKey: newIdempotencyKey() }),
    removeTarget: (projectId: string, targetId: string) =>
      request<void>("DELETE", `/projects/${enc(projectId)}/targets`, { body: { target_id: targetId } }),
    getScope: (projectId: string) => request<ScopePolicy>("GET", `/projects/${enc(projectId)}/scope`),
    updateScope: (projectId: string, scope: ScopePolicy) => request<ScopePolicy>("PUT", `/projects/${enc(projectId)}/scope`, { body: scope }),

    // pentests
    listRuns: (q: { cursor?: string; limit?: number; project_id?: string; status?: RunStatus; archived?: boolean } = {}) =>
      request<ListPage<Run>>("GET", "/pentests", { query: q }),
    createRun: (input: {
      project_id?: string;
      name: string;
      task?: string;
      authorized_target?: string;
      target_kind?: "local_project" | "github_repository" | "web_application";
      scan_mode?: "low" | "standard" | "high" | "deep";
      environment?: Schemas["RunEnvironment"];
      limits?: AgentLimits;
    }) => request<Run>("POST", "/pentests", { body: input, idempotencyKey: newIdempotencyKey() }),
    getRun: (runId: string) => request<Run>("GET", `/pentests/${enc(runId)}`),
    startRun: (runId: string) =>
      request<Run>("POST", `/pentests/${enc(runId)}/start`, { idempotencyKey: newIdempotencyKey() }),
    stopRun: (runId: string) => request<Run>("POST", `/pentests/${enc(runId)}/stop`),
    archiveRun: (runId: string) => request<Run>("POST", `/pentests/${enc(runId)}/archive`),
    unarchiveRun: (runId: string) => request<Run>("POST", `/pentests/${enc(runId)}/unarchive`),
    deleteRun: (runId: string) => request<void>("DELETE", `/pentests/${enc(runId)}`),
    listAgents: (runId: string) => request<{ items: Agent[] }>("GET", `/pentests/${enc(runId)}/agents`),
    postMessage: (runId: string, input: { to_agent_id: string; body: string; correlation_id?: string }) =>
      request<AgentMessage>("POST", `/pentests/${enc(runId)}/messages`, {
        body: input,
        idempotencyKey: newIdempotencyKey(),
      }),
    listRunFindings: (runId: string, q: { cursor?: string; limit?: number; severity?: FindingSeverity; status?: FindingStatus } = {}) =>
      request<ListPage<Finding>>("GET", `/pentests/${enc(runId)}/findings`, { query: q }),
    listRunTargets: (runId: string) => request<{ items: Target[] }>("GET", `/pentests/${enc(runId)}/targets`),
    getRunSnapshot: (runId: string) => request<RunSnapshot>("GET", `/pentests/${enc(runId)}/snapshot`),
    getRunEvents: (runId: string, afterSeq = 0, limit?: number) =>
      request<{ items: RunEvent[]; cursor: number }>("GET", `/pentests/${enc(runId)}/events`, {
        query: { after_seq: afterSeq, limit },
      }),

    // findings
    getFinding: (findingId: string) => request<Finding>("GET", `/findings/${enc(findingId)}`),
    updateFinding: (findingId: string, patch: { status?: FindingStatus; severity?: FindingSeverity; remediation?: string }) =>
      request<Finding>("PATCH", `/findings/${enc(findingId)}`, { body: patch }),

    // evidence
    getEvidence: (evidenceId: string) => request<Evidence>("GET", `/evidence/${enc(evidenceId)}`),
    listRunEvidence: (runId: string, q: { cursor?: string; limit?: number } = {}) => request<ListPage<Evidence>>("GET", `/pentests/${enc(runId)}/evidence`, { query: q }),

    // skills
    listSkills: (q: { query?: string; cursor?: string; limit?: number } = {}) =>
      request<ListPage<SkillRef>>("GET", "/skills", { query: q }),
    getSkill: (skillId: string, includeContent = true) =>
      request<{ skill: SkillRef; content?: string }>("GET", `/skills/${enc(skillId)}`, { query: { include_content: includeContent ? 1 : 0 } }),

    // settings
    getSettings: () => request<Settings>("GET", "/settings"),
    patchSettings: (patch: Settings) => request<Settings>("PATCH", "/settings", { body: patch }),

    // Local profile integrations; Cloud has a separate managed control plane.
    getProviderCatalog: () => request<ProviderCatalog>("GET", "/integrations/catalog"),
    refreshProviderCatalog: () => request<ProviderCatalog>("POST", "/integrations/catalog/refresh"),
    discoverProviderModels: (input: { id?: string; base_url: string; api_key?: string }) => request<Array<{ id: string; name: string }>>("POST", "/integrations/provider-models", { body: input }),
    listProviders: () => request<{ items: ProviderConnection[]; active_provider: string | null; runtime_provider: string; runtime_model: string }>("GET", "/integrations/providers"),
    saveProvider: (input: { id?: string | undefined; provider: string; label: string; model: string; base_url: string; api_key?: string | undefined }) => request<ProviderConnection>("POST", "/integrations/providers", { body: input }),
    activateProvider: (id: string) => request<unknown>("POST", `/integrations/providers/${enc(id)}/activate`),
    deleteProvider: (id: string) => request<void>("DELETE", `/integrations/providers/${enc(id)}`),
    checkProvider: (id: string) => request<{ state: string; detail: string }>("POST", `/integrations/providers/${enc(id)}/check`),
    getCodexStatus: () => request<CodexStatus>("GET", "/integrations/codex"),
    startCodexLogin: () => request<CodexLogin>("POST", "/integrations/codex/login"),
    logoutCodex: () => request<void>("DELETE", "/integrations/codex/login"),
    getMemoryConfig: () => request<MemoryConfig>("GET", "/integrations/memory"),
    getNvdConfig: () => request<{ key_configured: boolean; requests_per_30_seconds: number }>("GET", "/integrations/nvd"),
    listNativeTools: () => request<IntegrationSchemas["NativeToolsDTO"]>("GET", "/integrations/tools"),
    provisionTools: () => request<IntegrationSchemas["NativeToolsDTO"]>("POST", "/integrations/tools/provision"),
    checkNativeTool: (id: string) => request<{ state: string; detail: string }>("POST", `/integrations/tools/${enc(id)}/check`),
    saveNvdKey: (api_key: string) => request<{ key_configured: boolean; requests_per_30_seconds: number }>("PUT", "/integrations/nvd", { body: { api_key } }),
    clearNvdKey: () => request<{ key_configured: boolean; requests_per_30_seconds: number }>("DELETE", "/integrations/nvd"),
    setupMemory: (input: { provider_connection_id: string; model: string; embedding_base_url: string; embedding_model: string; embedding_dimension: number; embedding_api_key?: string }) => request<MemoryConfig>("POST", "/integrations/memory/setup", { body: input }),
    autoStartMemory: () => request<unknown>("POST", "/integrations/memory/auto-start"),
    saveMemoryConfig: (input: { openviking_url: string; openviking_account: string; openviking_user: string; openviking_processing_mode: string; service_api_key?: string | undefined }) => request<MemoryConfig>("PUT", "/integrations/memory", { body: input }),
    generateMemoryConfig: (input: { language_base_url: string; language_model: string; language_api_key?: string | undefined; embedding_base_url: string; embedding_model: string; embedding_dimension: number; embedding_api_key?: string | undefined }) => request<MemoryConfig>("POST", "/integrations/memory/server-config", { body: input }),
    checkMemory: () => request<ServiceStatus>("POST", "/integrations/memory/check"),
    startLocalMemory: () => request<MemoryConfig>("POST", "/integrations/memory/start"),

    // reports
    listReports: (runId: string, cursor?: string) =>
      request<ListPage<Report>>("GET", "/reports", { query: { run_id: runId, cursor, limit: 200 } }),
    createReport: (runId: string, format: "html" | "json" | "pdf") =>
      request<Report>("POST", `/pentests/${enc(runId)}/reports`, { body: { format }, idempotencyKey: newIdempotencyKey() }),
    getReport: (reportId: string) => request<Report>("GET", `/reports/${enc(reportId)}`),
    downloadReport: async (report: Report) => {
      const token = await cfg.getToken();
      const response = await fetchFn(`${cfg.baseUrl}/reports/${enc(report.report_id)}/download`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}, signal: AbortSignal.timeout(60_000),
      });
      if (!response.ok) throw new ApiError(response.status, "report_download_failed", "Cannot download the report artifact.");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = url; link.download = `${report.report_id}.${report.format}`;
      document.body.append(link); link.click(); link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;

function enc(s: string): string {
  return encodeURIComponent(s);
}

/**
 * Follow every cursor; never display a silently truncated session/result list.
 * Bounded by `maxPages` (a generous finite default, not Infinity) so a buggy or
 * hostile engine returning ever-distinct cursors cannot drive an unbounded
 * fetch loop and exhaust renderer memory. The repeated-cursor guard catches the
 * common cycle; this cap catches the monotonic-cursor case.
 */
export async function listAll<T>(
  pageFn: (cursor: string | undefined) => Promise<ListPage<T>>,
  maxPages = 10_000,
): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  const seen = new Set<string>();
  for (let i = 0; i < maxPages; i++) {
    const page = await pageFn(cursor);
    out.push(...(page.items ?? []));
    if (!page.next_cursor) return out;
    if (seen.has(page.next_cursor)) throw new ApiError(502, "pagination_cycle", "The engine returned a repeated page cursor. Refresh the list.");
    seen.add(page.next_cursor);
    cursor = page.next_cursor;
  }
  throw new ApiError(502, "pagination_limit", "The result list exceeded the requested page limit.");
}
