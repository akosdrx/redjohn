/**
 * GENERATED FILE — DO NOT HAND-EDIT.
 * Generated from contracts/openapi.yaml by `pnpm schema:generate`
 * (app/scripts/generate-schema.mjs). Regenerate after any contract change.
 */
export interface paths {
    "/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Service health overview (API, OpenViking, MCPs, worker) */
        get: operations["getStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/capabilities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Engine capabilities and configured limits */
        get: operations["getCapabilities"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listProjects"];
        put?: never;
        post: operations["createProject"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{project_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getProject"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch: operations["updateProject"];
        trace?: never;
    };
    "/projects/{project_id}/targets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["addTarget"];
        delete: operations["removeTarget"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/projects/{project_id}/scope": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getScope"];
        /** Creates a new scope version. Active runs keep their pinned version. */
        put: operations["replaceScope"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listRuns"];
        put?: never;
        /** Create a pentest run (status=created). Idempotent via Idempotency-Key. */
        post: operations["createRun"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getRun"];
        put?: never;
        post?: never;
        /** Stop any active agents and delete the session and its owned artifacts. */
        delete: operations["deleteRun"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List every artifact captured for this session, including artifacts without findings. */
        get: operations["listRunEvidence"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/archive": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Stop an active session and archive it while retaining all results. */
        post: operations["archiveRun"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/unarchive": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore an archived session to the session list. */
        post: operations["unarchiveRun"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Start the run. Idempotent via Idempotency-Key. */
        post: operations["startRun"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/stop": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Stop run: blocks new delegation, then stops children and tool processes. Existing findings remain available. */
        post: operations["stopRun"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/agents": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listAgents"];
        put?: never;
        /** Server-side validated agent creation (supervisor). Enforces depth/scope/tool/budget narrowing and capacity limits. */
        post: operations["createAgent"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/messages": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Send a model message to an agent (not a shell command). Idempotent via Idempotency-Key. */
        post: operations["postMessage"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listRunFindings"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/targets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listRunTargets"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/snapshot": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Consistent state snapshot + event cursor for (re)hydration */
        get: operations["getRunSnapshot"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Replay events after seq (gap fill on reconnect) */
        get: operations["getRunEvents"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/pentests/{run_id}/stream": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** WebSocket live stream of RunEvents (backpressure-aware; replay+live handoff without loss) */
        get: operations["streamRun"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings/{finding_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getFinding"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch: operations["updateFinding"];
        trace?: never;
    };
    "/evidence/{evidence_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Metadata; content via ?download=1 with access check */
        get: operations["getEvidence"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listEvidence"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/mcps": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listMCPs"];
        put?: never;
        /** Local products only; cloud uses provider-managed catalog */
        post: operations["createMCP"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/mcps/{mcp_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Re-initialize connection and re-discover tools */
        post: operations["reconnectMCP"];
        delete: operations["deleteMCP"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/skills": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Search/filter/paginate skills (backed by OpenViking) */
        get: operations["listSkills"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/skills/{skill_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Skill detail; content loaded on demand */
        get: operations["getSkill"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/settings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSettings"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch: operations["patchSettings"];
        trace?: never;
    };
    "/pentests/{run_id}/reports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["createReport"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/reports/{report_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getReport"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/reports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listReports"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        ListPage: {
            next_cursor?: string | null;
            total?: number | null;
        };
        ErrorResponse: {
            error: {
                code: string;
                message: string;
                details?: Record<string, never>;
                request_id?: string;
            };
        };
        /** @enum {string} */
        RunEnvironment: "local" | "cloud_managed";
        /** @enum {string} */
        RunStatus: "created" | "starting" | "running" | "stopping" | "stopped" | "completed" | "failed";
        /** @enum {string} */
        AgentStatus: "pending" | "queued" | "running" | "waiting" | "complete" | "failed" | "stopped";
        /** @enum {string} */
        AgentRole: "coordinator" | "specialist" | "worker";
        /** @enum {string} */
        TargetKind: "domain" | "url" | "ipv4" | "ipv6" | "cidr" | "hostname" | "local_project" | "github_repository";
        /** @enum {string} */
        PentestTargetKind: "local_project" | "github_repository" | "web_application";
        /**
         * @default standard
         * @enum {string}
         */
        ScanMode: "low" | "standard" | "high" | "deep";
        /** @enum {string} */
        VerificationStatus: "unverified" | "pending" | "verified" | "rejected";
        /** @enum {string} */
        FindingSeverity: "critical" | "high" | "medium" | "low" | "info";
        /** @enum {string} */
        FindingStatus: "observation" | "suspected" | "verified" | "ready_for_review" | "resolved" | "false_positive";
        /** @enum {string} */
        ServiceState: "live" | "starting" | "degraded" | "down" | "not_configured";
        /** @enum {string} */
        MCPTransport: "stdio" | "streamable_http";
        Workspace: {
            workspace_id: string;
            name: string;
            slug: string;
            /** @enum {string} */
            kind?: "local" | "cloud";
            /** Format: date-time */
            created_at?: string;
        };
        Project: {
            project_id: string;
            workspace_id: string;
            name: string;
            description?: string;
            /** Format: date-time */
            created_at?: string;
        };
        Target: {
            target_id: string;
            project_id: string;
            value: string;
            kind: components["schemas"]["TargetKind"];
            verification?: components["schemas"]["VerificationStatus"];
            note?: string;
            /** Format: date-time */
            created_at?: string;
        };
        ScopePolicy: {
            scope_id: string;
            project_id: string;
            version: number;
            allowed_targets?: string[];
            allowed_tools?: string[];
            denied_tools?: string[];
            /** @default 24 */
            max_agents: number;
            /** @default 6 */
            max_concurrent_agents: number;
            /** @default 3 */
            max_depth: number;
            notes?: string;
            /** Format: date-time */
            created_at?: string;
        };
        AgentLimits: {
            /** @default 6 */
            max_concurrent_agents: number;
            /** @default 24 */
            max_total_agents: number;
            /** @default 3 */
            max_delegation_depth: number;
            time_budget_seconds?: number | null;
            token_budget?: number | null;
        };
        Run: {
            run_id: string;
            workspace_id: string;
            project_id: string;
            name: string;
            /** @description short human ref, e.g. RJ-024 (per-workspace sequence) */
            ref?: string;
            task?: string;
            scan_mode?: components["schemas"]["ScanMode"];
            authorized_target?: string | null;
            target_kind?: components["schemas"]["PentestTargetKind"] | null;
            /** @default false */
            session_project: boolean;
            /** Format: date-time */
            archived_at?: string | null;
            status: components["schemas"]["RunStatus"];
            scope: components["schemas"]["ScopePolicy"];
            limits?: components["schemas"]["AgentLimits"];
            environment?: components["schemas"]["RunEnvironment"];
            /** Format: date-time */
            created_at?: string;
            /** Format: date-time */
            started_at?: string | null;
            /** Format: date-time */
            finished_at?: string | null;
            error?: string | null;
        };
        Agent: {
            agent_id: string;
            run_id: string;
            parent_agent_id?: string | null;
            role?: components["schemas"]["AgentRole"];
            name: string;
            task: string;
            status: components["schemas"]["AgentStatus"];
            depth: number;
            allowed_targets?: string[];
            allowed_tools?: string[];
            current_activity?: string;
            ov_session_uri?: string | null;
            /** Format: date-time */
            created_at?: string;
            /** Format: date-time */
            finished_at?: string | null;
        };
        AgentMessage: {
            message_id: string;
            run_id: string;
            from_agent_id: string;
            to_agent_id: string;
            correlation_id?: string | null;
            /** @enum {string} */
            kind?: "instruction" | "result" | "query" | "broadcast";
            body: string;
            summary_ref?: string | null;
            evidence_refs?: string[];
            /** @enum {string} */
            status: "queued" | "delivered" | "read" | "failed";
            /** Format: date-time */
            created_at?: string;
            /** Format: date-time */
            delivered_at?: string | null;
        };
        ToolInvocation: {
            invocation_id: string;
            run_id: string;
            agent_id: string;
            tool: string;
            args?: Record<string, never>;
            /** @enum {string} */
            status: "started" | "completed" | "failed" | "timed_out" | "cancelled" | "unknown";
            attempt?: number;
            exit_code?: number | null;
            output_ref?: string | null;
            evidence_refs?: string[];
            /** Format: date-time */
            started_at?: string;
            /** Format: date-time */
            finished_at?: string | null;
            error?: string | null;
        };
        Finding: {
            finding_id: string;
            run_id: string;
            code: string;
            title: string;
            severity: components["schemas"]["FindingSeverity"];
            status: components["schemas"]["FindingStatus"];
            target?: string;
            source_agent_id?: string | null;
            description?: string;
            evidence_refs?: string[];
            remediation?: string;
            /** Format: date-time */
            created_at?: string;
            /** Format: date-time */
            updated_at?: string;
        };
        Evidence: {
            evidence_id: string;
            run_id: string;
            sha256: string;
            mime: string;
            size_bytes: number;
            source: string;
            storage_ref: string;
            /** @enum {string} */
            access?: "workspace" | "run" | "restricted";
            redacted?: boolean;
            /** Format: date-time */
            created_at?: string;
        };
        SkillRef: {
            skill_id: string;
            name: string;
            version: string;
            description?: string;
            source?: string;
            ov_uri?: string | null;
            content_hash?: string;
            required_tools?: string[];
            environments?: ("local" | "cloud_worker" | "any")[];
            execution_rules?: string;
        };
        MCPConnection: {
            mcp_id: string;
            name: string;
            transport: components["schemas"]["MCPTransport"];
            command?: string[];
            url?: string | null;
            status: components["schemas"]["ServiceState"];
            tools?: string[];
            error?: string | null;
            /** Format: date-time */
            created_at?: string;
        };
        ServiceStatus: {
            service: string;
            state: components["schemas"]["ServiceState"];
            detail?: string;
            latency_ms?: number | null;
            /** Format: date-time */
            checked_at?: string;
        };
        RunEvent: {
            /** @constant */
            schema_version: 1;
            event_id: string;
            workspace_id: string;
            run_id: string;
            seq: number;
            /** Format: date-time */
            occurred_at: string;
            /** @enum {string} */
            type: "run.status" | "agent.status" | "agent.activity" | "agent.message" | "tool.invocation.started" | "tool.invocation.output" | "tool.invocation.completed" | "finding.created" | "finding.updated" | "target.updated" | "service.status" | "terminal.output" | "usage.event";
            agent_id?: string | null;
            correlation_id?: string | null;
            data: Record<string, never>;
        };
        Settings: {
            /** @description e.g. anthropic; API keys never returned */
            model_provider?: string;
            model_name?: string;
            openviking_url?: string;
            data_profile?: string;
            log_level?: string;
        };
        Report: {
            report_id: string;
            run_id: string;
            /** @enum {string} */
            format: "html" | "json" | "pdf";
            storage_ref?: string;
            /** Format: date-time */
            created_at: string;
        };
    };
    responses: {
        /** @description Not found */
        NotFound: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["ErrorResponse"];
            };
        };
        /** @description State conflict (e.g. invalid transition, duplicate idempotency key with different payload) */
        Conflict: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["ErrorResponse"];
            };
        };
        /** @description Authorization / scope / entitlement denial */
        Forbidden: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["ErrorResponse"];
            };
        };
        /** @description Validation error */
        ValidationError: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["ErrorResponse"];
            };
        };
    };
    parameters: {
        Cursor: string;
        Limit: number;
        IdempotencyKey: string;
        ProjectId: string;
        RunId: string;
        FindingId: string;
        EvidenceId: string;
    };
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    getStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Service states; "live" only for fresh, authorized, usable connections */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        /** @example 1 */
                        contract_version: string;
                        engine_version?: string;
                        services: components["schemas"]["ServiceStatus"][];
                    };
                };
            };
        };
    };
    getCapabilities: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Capability descriptor */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        environment?: components["schemas"]["RunEnvironment"];
                        limits?: components["schemas"]["AgentLimits"];
                        /** @description real OpenViking server configured */
                        openviking?: boolean;
                        mcp_transports?: ("stdio" | "streamable_http")[];
                        pty?: boolean;
                        reports?: ("html" | "json" | "pdf")[];
                    };
                };
            };
        };
    };
    listProjects: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of projects */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["Project"][];
                    };
                };
            };
        };
    };
    createProject: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    name: string;
                    description?: string;
                };
            };
        };
        responses: {
            /** @description Created */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Project"];
                };
            };
            409: components["responses"]["Conflict"];
        };
    };
    getProject: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_id: components["parameters"]["ProjectId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Project with targets and scope */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        project?: components["schemas"]["Project"];
                        targets?: components["schemas"]["Target"][];
                        scope?: components["schemas"]["ScopePolicy"];
                    };
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    updateProject: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_id: components["parameters"]["ProjectId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    name?: string;
                    description?: string;
                };
            };
        };
        responses: {
            /** @description Updated */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Project"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    addTarget: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path: {
                project_id: components["parameters"]["ProjectId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    value: string;
                    kind: components["schemas"]["TargetKind"];
                    note?: string;
                };
            };
        };
        responses: {
            /** @description Created */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Target"];
                };
            };
        };
    };
    removeTarget: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_id: components["parameters"]["ProjectId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    target_id: string;
                };
            };
        };
        responses: {
            /** @description Removed */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            404: components["responses"]["NotFound"];
        };
    };
    getScope: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_id: components["parameters"]["ProjectId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Current scope policy (latest version) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScopePolicy"];
                };
            };
        };
    };
    replaceScope: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                project_id: components["parameters"]["ProjectId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ScopePolicy"];
            };
        };
        responses: {
            /** @description New scope version */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScopePolicy"];
                };
            };
            409: components["responses"]["Conflict"];
        };
    };
    listRuns: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
                project_id?: string;
                status?: components["schemas"]["RunStatus"];
                archived?: boolean;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of runs */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["Run"][];
                    };
                };
            };
        };
    };
    createRun: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    project_id?: string;
                    name: string;
                    /** @default  */
                    task?: string;
                    scan_mode?: components["schemas"]["ScanMode"];
                    /** @description Required when project_id is omitted */
                    authorized_target?: string;
                    target_kind?: components["schemas"]["PentestTargetKind"];
                    environment?: components["schemas"]["RunEnvironment"];
                    limits?: components["schemas"]["AgentLimits"];
                };
            };
        };
        responses: {
            /** @description Created (scope pinned to current project scope version) */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Run"];
                };
            };
            409: components["responses"]["Conflict"];
            422: components["responses"]["ValidationError"];
        };
    };
    getRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Run detail */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Run"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    deleteRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Session deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            404: components["responses"]["NotFound"];
        };
    };
    listRunEvidence: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of session evidence */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["Evidence"][];
                    };
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    archiveRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Archived session */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Run"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    unarchiveRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Restored session */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Run"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    startRun: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Run transitioning to starting/running */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Run"];
                };
            };
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
        };
    };
    stopRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Run transitioning to stopping/stopped */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Run"];
                };
            };
            409: components["responses"]["Conflict"];
        };
    };
    listAgents: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Agents of the run (tree via parent_agent_id) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        items?: components["schemas"]["Agent"][];
                    };
                };
            };
        };
    };
    createAgent: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    parent_agent_id: string;
                    name: string;
                    role: components["schemas"]["AgentRole"];
                    task: string;
                    allowed_targets?: string[];
                    allowed_tools?: string[];
                };
            };
        };
        responses: {
            /** @description Created */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Agent"];
                };
            };
            403: components["responses"]["Forbidden"];
            409: components["responses"]["Conflict"];
        };
    };
    postMessage: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    to_agent_id: string;
                    body: string;
                    correlation_id?: string;
                };
            };
        };
        responses: {
            /** @description Queued */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgentMessage"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    listRunFindings: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
                severity?: components["schemas"]["FindingSeverity"];
                status?: components["schemas"]["FindingStatus"];
            };
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of findings */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["Finding"][];
                    };
                };
            };
        };
    };
    listRunTargets: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Effective targets of the run (pinned scope resolution) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        items?: components["schemas"]["Target"][];
                    };
                };
            };
        };
    };
    getRunSnapshot: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Snapshot with event cursor */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        run: components["schemas"]["Run"];
                        agents: components["schemas"]["Agent"][];
                        findings?: components["schemas"]["Finding"][];
                        services?: components["schemas"]["ServiceStatus"][];
                        /** @description last included event seq */
                        cursor: number;
                    };
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    getRunEvents: {
        parameters: {
            query?: {
                after_seq?: number;
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Ordered events; 410 when cursor expired by retention (resnapshot) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        items?: components["schemas"]["RunEvent"][];
                        cursor?: number;
                    };
                };
            };
            /** @description Cursor expired; client must refetch snapshot */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorResponse"];
                };
            };
        };
    };
    streamRun: {
        parameters: {
            query?: {
                after_seq?: number;
            };
            header?: never;
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description WebSocket upgrade */
            101: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Finding detail */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Finding"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    updateFinding: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                finding_id: components["parameters"]["FindingId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    status?: components["schemas"]["FindingStatus"];
                    severity?: components["schemas"]["FindingSeverity"];
                    remediation?: string;
                };
            };
        };
        responses: {
            /** @description Updated */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Finding"];
                };
            };
        };
    };
    getEvidence: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                evidence_id: components["parameters"]["EvidenceId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Evidence metadata (hash, mime, size, source, access rule) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Evidence"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    listEvidence: {
        parameters: {
            query: {
                run_id: string;
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of evidence metadata */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["Evidence"][];
                    };
                };
            };
        };
    };
    listMCPs: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Configured MCP connections with live status */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        items?: components["schemas"]["MCPConnection"][];
                    };
                };
            };
        };
    };
    createMCP: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["MCPConnection"];
            };
        };
        responses: {
            /** @description Created */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MCPConnection"];
                };
            };
            403: components["responses"]["Forbidden"];
        };
    };
    reconnectMCP: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                mcp_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Connection status after reconnect */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MCPConnection"];
                };
            };
        };
    };
    deleteMCP: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                mcp_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            404: components["responses"]["NotFound"];
        };
    };
    listSkills: {
        parameters: {
            query?: {
                query?: string;
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of skill metadata */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["SkillRef"][];
                    };
                };
            };
        };
    };
    getSkill: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                skill_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Skill with content when requested */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        skill?: components["schemas"]["SkillRef"];
                        /** @description only when ?include_content=1 */
                        content?: string;
                    };
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    getSettings: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Redacted settings (secrets never returned) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Settings"];
                };
            };
        };
    };
    patchSettings: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["Settings"];
            };
        };
        responses: {
            /** @description Updated, redacted settings */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Settings"];
                };
            };
        };
    };
    createReport: {
        parameters: {
            query?: never;
            header?: {
                "Idempotency-Key"?: components["parameters"]["IdempotencyKey"];
            };
            path: {
                run_id: components["parameters"]["RunId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    /** @enum {string} */
                    format: "html" | "json" | "pdf";
                };
            };
        };
        responses: {
            /** @description Report artifact */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Report"];
                };
            };
        };
    };
    getReport: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                report_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Report artifact */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Report"];
                };
            };
            404: components["responses"]["NotFound"];
        };
    };
    listReports: {
        parameters: {
            query: {
                run_id: string;
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of reports */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListPage"] & {
                        items?: components["schemas"]["Report"][];
                    };
                };
            };
        };
    };
}
