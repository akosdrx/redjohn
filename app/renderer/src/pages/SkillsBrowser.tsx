import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button, EmptyState, ErrorState, Input, Panel, Spinner, cn } from "@redjohn/ui";
import { useEngine } from "../lib/engine";

/** Only the current server page is rendered; search resets its cursor. */
export function SkillsBrowser() {
  const { api } = useEngine();
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const [selectedSkill, setSelectedSkill] = useState<string | null>(null);
  const detail = useQuery({
    queryKey: ["skill-content", selectedSkill],
    queryFn: () => api!.getSkill(selectedSkill!, true),
    enabled: !!api && !!selectedSkill,
  });
  const cursor = cursors.at(-1);
  const skills = useQuery({
    queryKey: ["skill-browser", query, cursor],
    queryFn: () => api!.listSkills({ limit: 50, ...(query ? { query } : {}), ...(cursor ? { cursor } : {}) }),
    enabled: !!api,
    gcTime: 30_000,
  });

  return (
    <Panel
      aria-label="Skill browser"
      title="Skill List"
      headerRight={
        <div role="status" className="flex items-center gap-1.5 text-[11px] text-rj-text-3">
          {skills.isFetching && <Spinner className="size-3.5" />}
          <span>{skills.isFetching ? "Loading skills…" : `Page ${cursors.length + 1} · ${skills.data?.total ?? "—"} skills`}</span>
        </div>
      }
      padded
    >
      <div className="flex flex-col gap-3">
        <form
          className="flex items-center gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            setQuery(draft.trim());
            setCursors([]);
          }}
        >
          <Input
            type="search"
            aria-label="Search skills"
            placeholder="Search skills"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            className="min-w-0 flex-1"
          />
          <Button type="submit" variant="outline">
            Search
          </Button>
        </form>

        {skills.error && <ErrorState detail={skills.error.message} onRetry={() => skills.refetch()} />}

        <ul aria-label="Skills" className="max-h-72 divide-y divide-rj-border overflow-y-auto rounded-md border border-rj-border bg-rj-panel-sunken text-[13px]">
          {skills.data?.items?.map((skill) => (
            <li key={skill.skill_id} title={skill.description}>
              <button
                type="button"
                aria-label={`Inspect skill ${skill.name}`}
                onClick={() => setSelectedSkill(skill.skill_id)}
                className={cn(
                  "flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-rj-panel-hover",
                  selectedSkill === skill.skill_id ? "bg-rj-panel-hover font-medium text-rj-text" : "text-rj-text-2",
                )}
              >
                <span className="truncate font-mono text-[12px]">{skill.name}</span>
                {skill.description && <span className="max-w-xs truncate text-[11px] text-rj-text-3">{skill.description}</span>}
              </button>
            </li>
          ))}
        </ul>

        {!skills.isPending && !skills.error && !skills.data?.items?.length && (
          <EmptyState title="No skills found." />
        )}

        <nav aria-label="Skills pages" className="flex items-center justify-end gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            aria-label="Previous skills page"
            disabled={!cursors.length || skills.isFetching}
            onClick={() => setCursors((current) => current.slice(0, -1))}
          >
            Previous
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            aria-label="Next skills page"
            disabled={!skills.data?.next_cursor || skills.isFetching}
            onClick={() => {
              if (skills.data?.next_cursor) setCursors((current) => [...current, skills.data.next_cursor!]);
            }}
          >
            Next
          </Button>
        </nav>

        {selectedSkill && (
          <section aria-label="Skill content" className="mt-1 border-t border-rj-border pt-3">
            <div className="mb-2 flex items-center justify-between">
              <h3 className="font-mono text-[13px] font-semibold text-rj-text">{detail.data?.skill.name ?? "Skill"}</h3>
              <Button type="button" size="sm" variant="ghost" onClick={() => setSelectedSkill(null)}>
                Close skill
              </Button>
            </div>
            {detail.isPending ? (
              <div role="status" className="flex items-center gap-2 py-4 text-[12px] text-rj-text-3">
                <Spinner className="size-4" />
                <span>Loading skill…</span>
              </div>
            ) : detail.isError ? (
              <ErrorState detail={detail.error.message} onRetry={() => detail.refetch()} />
            ) : (
              <pre className="max-h-96 overflow-y-auto whitespace-pre-wrap break-words rounded-md border border-rj-border bg-rj-panel-sunken p-3 font-mono text-[12px] text-rj-text-2">
                {detail.data?.content ?? "Content is unavailable for this skill."}
              </pre>
            )}
          </section>
        )}
      </div>
    </Panel>
  );
}
