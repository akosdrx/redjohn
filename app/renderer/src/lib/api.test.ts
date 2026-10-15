import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient, listAll } from "./api";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("api client", () => {
  it("sends the token in the Authorization header, never in the URL", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { services: [], contract_version: "1" }));
    const api = createApiClient({ baseUrl: "http://127.0.0.1:8720/api/v1", getToken: () => "sekret", fetchFn });
    await api.getStatus();
    const [url, init] = fetchFn.mock.calls[0]! as [string, RequestInit];
    expect(url).not.toContain("sekret");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer sekret");
  });

  it("follows cursor pagination via listAll", async () => {
    const pages = [
      { items: [1, 2], next_cursor: "c2", total: 5 },
      { items: [3, 4], next_cursor: "c3", total: 5 },
      { items: [5], next_cursor: null, total: 5 },
    ];
    let i = 0;
    const pageFn = vi.fn().mockImplementation(() => Promise.resolve(pages[i++]));
    const all = await listAll(pageFn);
    expect(all).toEqual([1, 2, 3, 4, 5]);
    expect(pageFn).toHaveBeenCalledTimes(3);
    expect(pageFn.mock.calls[1]![0]).toBe("c2");
  });

  it("loads more than twenty pages and rejects a repeated cursor", async () => {
    let page = 0;
    const pageFn = vi.fn(async () => ({ items: [page++], next_cursor: page < 25 ? `page-${page}` : null }));
    expect(await listAll(pageFn)).toHaveLength(25);
    const cyclic = vi.fn().mockResolvedValue({ items: [1], next_cursor: "same" });
    await expect(listAll(cyclic)).rejects.toMatchObject({ code: "pagination_cycle" });
  });

  it("throws typed ApiError from ErrorResponse bodies", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(409, { error: { code: "conflict", message: "invalid transition", request_id: "r1" } }),
    );
    const api = createApiClient({ baseUrl: "http://127.0.0.1:8720/api/v1", getToken: () => null, fetchFn });
    const err = await api.stopRun("run_1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(409);
    expect((err as ApiError).code).toBe("conflict");
  });

  it("sends Idempotency-Key on run create", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(201, {
        run_id: "r1", workspace_id: "w", project_id: "p", name: "n", status: "created",
        scope: { scope_id: "s", project_id: "p", version: 1 },
      }),
    );
    const api = createApiClient({ baseUrl: "http://127.0.0.1:8720/api/v1", getToken: () => "t", fetchFn });
    await api.createRun({ project_id: "p", name: "n", task: "t" });
    const [, init] = fetchFn.mock.calls[0]! as [string, RequestInit];
    expect((init.headers as Record<string, string>)["Idempotency-Key"]).toBeTruthy();
  });
});
