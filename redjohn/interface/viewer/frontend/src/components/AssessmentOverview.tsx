type RecordValue = Record<string, unknown>;

function record(value: unknown): RecordValue {
  return value && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {};
}

function rows(value: unknown): RecordValue[] {
  return Array.isArray(value) ? value.slice(0, 100).map(record) : [];
}

function label(value: unknown): string {
  return typeof value === "string" ? value.replaceAll("_", " ") : "unknown";
}

export function AssessmentOverview({ assessment }: { assessment: unknown }) {
  const data = record(assessment);
  if (data.read_only !== true) return null;
  const coverage = rows(data.coverage);
  const gaps = rows(data.capability_gaps);
  const candidates = typeof data.candidate_count === "number" ? data.candidate_count : null;

  return (
    <section aria-labelledby="assessment-heading" className="rounded-xl border border-white/20 bg-white/[0.02] p-5 text-sm text-white/80">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="assessment-heading" className="font-semibold text-white">Bounded assessment</h2>
        <span className="rounded-md border border-white/20 px-2 py-1 text-xs">Read-only report snapshot</span>
      </div>
      <p className="mt-3 leading-relaxed">
        {label(data.engagement_id)} · {candidates ?? "Unknown"} candidate matches on this report page.
        Candidates require validation and are separate from confirmed vulnerabilities.
      </p>
      {data.error ? (
        <p role="alert" className="mt-4 text-red-300">Assessment report unavailable. Check the report format and size.</p>
      ) : (
        <>
          <div className="mt-5 grid gap-3" role="list" aria-label="Assessment coverage">
            {coverage.map((row, index) => (
              <div key={index} role="listitem" className="grid min-w-0 grid-cols-1 gap-2 border-t border-white/15 pt-3 sm:grid-cols-[1fr_1fr_1fr]">
                <span className="min-w-0 break-words font-medium text-white">{label(row.family)}</span>
                <span>Execution: {label(row.execution_status)}</span>
                <span>Coverage: {label(row.coverage_status)} ({String(row.count ?? "?")})</span>
              </div>
            ))}
          </div>
          {gaps.length > 0 && (
            <div className="mt-5 border-t border-white/15 pt-4">
              <h3 className="font-medium text-white">Unavailable or deferred capabilities ({gaps.length})</h3>
              <ul className="mt-2 space-y-2 text-xs leading-relaxed">
                {gaps.slice(0, 5).map((gap, index) => (
                  <li key={index} className="break-words">{label(gap.id)} — {label(gap.status)}</li>
                ))}
              </ul>
              {gaps.length > 5 && <p className="mt-2 text-xs">The full list is in assessment-report.json.</p>}
              <p className="mt-3 leading-relaxed">Unavailable capabilities are coverage gaps, never negative vulnerability results.</p>
            </div>
          )}
          <p className="mt-4 text-xs leading-relaxed">
            Up to 100 jobs/findings are represented. Resume the assessment with the CLI and reload to see a new snapshot.
            {data.rce_regression === "not_reproduced_missing_fixture" && " Original RCE: not reproduced; fixture missing."}
          </p>
        </>
      )}
    </section>
  );
}
