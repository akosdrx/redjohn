# RedJohn host-binding — módosított fájlok

Ez a szakasz 21 Python-forrást és a scope-sablont érinti. A korábban meglévő
76 aktív Python teszt/support fájl byte-ra megmaradt; 7 új aktív tesztfájl készült,
43 új esettel. A felhasználó korábbi Git-átstrukturálása nem e szakasz törlése.
Az összes ellenőrzési artefaktum és aktuális hash a
[gépi fájljegyzékben](redjohn-host-binding-changed-files.json) szerepel.

| Fájl a `RedJohn/redjohn/` alatt | Változás |
|---|---|
| `assessment/configuration.py` | Új közös konfigurációs factory, seed/job-bekötés, kanonikus policy és közös riportmetrikák. |
| `assessment/host.py` | Új korlátos host-pump, policy/cancel/deadline állapot, audit és cleanup. |
| `assessment/host_binding.py` | Új host-jóváhagyás, privát HMAC snapshot v2, caller/UID/run-kötés és ismert privát utak. |
| `assessment/cli.py` | Közös factory/metrikák használata és pontosított resource-recovery help. |
| `assessment/control.py` | Lezárt API stabil hibája, host-admission callbackek, mutáló jobok nem idempotens szerződése. |
| `assessment/policy.py` | Hálózatmentes inventory-jogosultság külön a worker egress-ellenőrzésétől. |
| `assessment/runtime.py` | Minden tulajdonolt komponens cleanupja korábbi close-hiba esetén is. |
| `assessment/scheduler.py` | Hibás persisted refresh/capture és mutáló job retry-jelzőjének elutasítása. |
| `assessment/store.py` | Callerhez kötött tartós stop-flag lekérdezése. |
| `core/runner.py` | Root/child service és governor context, inert MCP-regisztráció, teljes korai cleanup és byte-megőrző hibás resume. |
| `interface/cli_args.py` | `--assessment-config` argumentum. |
| `interface/cli.py` | A host-konfiguráció továbbítása a közös runnernek. |
| `interface/tui/runtime.py` | Ugyanazon host-konfiguráció továbbítása a TUI-ból. |
| `runtime/session_manager.py` | Ismert control-plane utak readonly bind-mountjai és cached session ellenőrzése. |
| `agents/prompts/scope.jinja` | Az engedélyezett host-service szűkített metadata-ja és az `assessment_control` használata. |

Új aktív tesztek a `RedJohn/tests/` alatt:

- `test_host_assessment_contract.py` — lezárt API, startup/report/component-close hibainjektálás;
- `test_host_assessment_live.py` — valódi SDK/Chromium/Nuclei restart/fixed és job-budget;
- `test_host_binding_contract.py` — jogosultság, metadata-only indulás, privát utak és revision;
- `test_host_binding_failures.py` — hibás MAC/kulcs, másik run, FD- és tempfájl-takarítás;
- `test_host_job_contract.py` — mutáló jobok retry-jelzője workerindítás előtt;
- `test_host_lifecycle_live.py` — valódi HTTPS cancel/deadline és külső processz-lock;
- `test_runner_assessment_contract.py` — root/child SDK-bekötés, startup/takarítás, hibás és szabályos resume.

Dokumentáció:

- `RedJohn/docs/host-bound-assessment.md` — angol indítási, jogosultsági és életciklus-leírás;
- `docs/redjohn-host-binding-verification.md` — tényleges parancsok, E2E/kontraktus szétválasztás, hibák és mérések;
- `docs/redjohn-completion-status.md` — a teljes master prompt megmaradó hatóköre;
- `docs/measurements/host-binding/` — JUnit, idő/RSS, forráshash, eredmények, megőrzés és recoverable cleanup.

A javított teljes kör Linuxon 1225/1225, macOS-en 1154 sikeres / 71 kernel-skip,
hiba nélkül. Mindkét platform strict mypy-ja 204 production modulon sikeres.
Ez a közös bekötés ellenőrzése; a teljes felhasználói UI/legacy-tool policy-
integráció, régi cache-migráció és a többi master-feladat továbbra is nyitott.
