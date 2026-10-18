# Completed intermediate hosted check

[Run 39149776625](https://github.com/akosdrx/redjohn/actions/runs/39149776625)
completed with **failure on both architectures**. Source head:
`18019b9010440a155625a6e11f9ed02273542851`; executed PR merge:
`8120baa33303decaf856dbcd54779be79589c002`; tree:
`33f6415f2145faf5c426541bc8c31320617bf8dc`. The merge's parents and tree were
independently checked against the published candidate.

| Native Ubuntu 24.04 platform | Regression | Actual integration | Frontend | Go |
| --- | --- | --- | --- | --- |
| x64 / Python 3.13.16 | 1081 passed, 1 failed | 350 passed, 4 failed | 14 passed | 21 passed |
| ARM64 / Python 3.12.3 | 1081 passed, 1 failed | 350 passed, 4 failed | 14 passed | 21 passed |

All four selections had zero test skips/errors. The frontend count includes
six explicitly classified fetch-double contracts and eight unit/render cases;
it is not fourteen network E2Es. The strict Python type/lint, frontend checks,
Go race/vet/build and distribution checks passed on this intermediate source.

The remaining failures are the same legacy GET test oracle, two Semgrep
initialization cases and two extended XML/UTF-16 Nuclei template cases described
in [the earlier failed candidate](redjohn-github-actions-master-phase2.md).
Their corrected code was published in the subsequent phase 3 source. This
intermediate run does not contain those fixes and is retained as a failed run.

Both real mixed browser/scanner soaks completed 120 cycles with zero duplicate
restart requests and successful owned cleanup. x64 elapsed 1206.612 s, p50
3.103 s and p95 3.627 s; ARM64 elapsed 1205.663 s, p50 3.276 s and p95 3.421 s.
These successful soak selections do not override the failed overall result.

All **668 source hashes** and **222 indexed artifact hashes** match independently
on each platform. GitHub artifact ZIP digests also match:

- x64: `b7f22ef2f68b93233df376536533348998281c8fcf616b170259103fd5a7e384`
- ARM64: `bf0ffe3bdcd8447ab10aaca0e6710d72a2c4ce867e8724b810d6b1a461596fee`

Original full job logs, JUnit, tool/resource data, terminal job status and
independent verification are retained under
`docs/measurements/master-completion-20261018/github-phase2-hotfix2/`. The current
local Git HEAD/index and private MCP configuration were preserved independently;
no full local regression replaced this hosted run.
