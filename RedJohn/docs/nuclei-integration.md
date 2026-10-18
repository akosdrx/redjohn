# RedJohn Nuclei / hunt integráció

## Tényleges kiindulópont és állapot (2026-10-17)

A korábbi Darwin/loopback számszerű mérések történeti baseline-ok. A jelenlegi
kód Linux kernelből attesztált remote-egresst és host-only exact-request auth-
replayt is támogat; ezek saját [remote/auth dokumentációval](remote-egress-auth.md)
és külön tényleges E2E-tesztekkel rendelkeznek. Egy régi loopback teszt vagy
namespace-only eredmény nem igazolja automatikusan a teljes új láncot.

A meglévő motorhívás a `redjohn/tools/hunt/tool.py` `hunt(kind="cve")` ága volt. Ugyanaz a sandbox-CLI útvonal maradt; nem került be második Nuclei, Strix vagy HexStrike platform. A korábbi kód globális `-tags cve,rce`/severity szelekciót, végén vágott stdoutot és szabad kézi exec fallbacket használt. Ez nem igazolt template-engedélyezést vagy memóriahatárt.

Az első auditkor hiányzó motor most **feloldott képességhiány**. A 2026-10-17-i hivatalos GitHub Releases API ellenőrzéskor a legfrissebb stabil kiadás **v3.11.1**, source commit `a8c88feb4a1c8e961b7902534ce3af97e9d524a4` volt. A helyi Darwin arm64 motor a repository `.tools/nuclei/3.11.1/` privát könyvtárába került; globális executable vagy meglévő telepítés nem lett felülírva. A ZIP beégetett SHA256 pinjét és a külön SHA256-pinnelt upstream checksumfájlt is ellenőriztük; ez tartalomazonosság-ellenőrzés, nem független kriptográfiai aláírás.

A tényleges executable SHA256: `f427ae885dcd60be25cf27c34a416ef18a803b29e153d5568057d7b6012a454d`; mérete **136853122 B**. A verziót a saját bounded supervisoron keresztüli `-version` healthcheck is igazolta. A [provenance receipt](nuclei-engine-provenance.json) tartalmazza a release URL-t, commitot, archívum-, checksumfájl-, executable- és MIT licence-digestet. Teljes upstream templates-készlet nem került letöltésre. A kiválasztott egyetlen template RedJohn saját ártalmatlan, Apache-2.0 SPDX-jelölt loopback-fixture-je. Valós HTTP- és HTTPS-scan kizárólag a saját helyi fixture ellen futott.

## Implementáció

- `redjohn/tools/hunt/nuclei.py`: külön bináris-/bundle-lock, típusos bounded opciók, explicit template ID/profile/effect/protocol szelekció, teljes file-map digest, előkészítés, healthcheck, parser, cancel/cleanup.
- `redjohn/tools/hunt/bounded_worker.py`: megbízható sandbox-oldali Python supervisor; folyamatosan, külön ürített stdout/stderr, bájthatár, deadline, TERM/KILL processgroup cleanup. A már ellenőrzött templates-fájlokról privát snapshot készül, ismételt digestellenőrzéssel. A scanner izolált ideiglenes HOME/configot kap, az automatikus public/private template-download változók tiltottak.
- `redjohn/tools/hunt/tool.py`: mind a négy hunt-fajta explicit policyt és közös ResourceGovernort igényel; nincs exec-fallback. Commix csak isolated-lab, SQLi/XSS csak active-staging/isolated-lab profilban. Egy specialist kiválasztása nem indítja automatikusan a többit.
- `scripts/install-kali.sh`: meglévő templates alapból megőrizve. Csak explicit `REDJOHN_UPDATE_NUCLEI_TEMPLATES=1` kér külön installkori update-et; hibája nincs elnyomva, utána új review/lock kell.

A Nuclei input GET/HEAD HTTP(S) template, statikus `{{BaseURL}}`/`{{RootURL}}` path,
helyi matcher. Anonymous mellett host-only vaultból pontos observed GET/HEAD
requesthez, actor/tenant/session-/policyrevisionhöz és lejárathoz kötött auth-replay
engedhető. Raw request, POST/body replay, DSL/interpolation, payload/variable,
redirect, OAST, YAML alias/anchor, code/file/headless/workflow és más protokoll
nincs engedélyezve. Nem kompatibilis template **unsupported/blocked**, nem negatív.

Határok: 128 bundle-fájl, fájlonként 64 KiB, összesen 4 MiB; 1 scanner concurrency és batch; max 10 request/s (default 5); 1–180 s scanner deadline; 1–20 s HTTP timeout; 1 MiB response read limit; külön stdout/stderr default 64 KiB, legfeljebb 256 KiB; nulla rejtett scanner retry. A kernel/cgroup hard RAM-limit továbbra is külön infrastruktúra-képesség. A távoli worker hálózati határát a LinuxEgressBoundary kernelattesztációja adja, nem a Python supervisor vagy egy policystring. Ennek hiányában a remote job blokkolt.

A schedulerhez kötött útvonal a `BrowserEgressProxy` saját literal-loopback listenerén át futtatja a motort: `-proxy <host-bound-url> -proxy-internal`. A `NativeFixtureSession.bind_proxy(url)` kizárólag controllerkódból köti a pontos URL-t; job/LLM-opció nem adhat tetszőleges proxyt. Aktív worker alatt a kötés nem változtatható. Minden tényleges kérés a közös scope/read-only/rate/request-budget szabályon megy át; a HTTPS upstream CA/hostname ellenőrzése a TLS-intercept proxyban szigorú. Nincs rendszertruststore-módosítás vagy upstream TLS-ellenőrzést kikapcsoló flag. A Nuclei natív Go TLS-viselkedését önmagában nem állítjuk megbízható CA-validációnak. Közvetlen HTTPS-hívást host-bound proxy és válaszobserver nélkül az adapter `https_requires_verified_egress_proxy` hibával még engine-indítás előtt visszautasít; a NativeFixtureSession is megtagadja az ilyen scan argv-t.

A `-stats-json` elhagyásra került: az implicit metrics-listener nem szükséges. Ambient proxyváltozók nem jutnak a child környezetébe; a kimeneti observer csak a kiválasztott, explicit proxyhoz kötött futás teljes, framing-ellenőrzött válaszairól ad URL/státusz/szűk header-metaadat rekordot.

Authenticated scheduler-jobhoz a `NucleiPipelineAdapter` a vault mellett a
request-evidence actor/tenant/session/URL/metódus és `sent` adatait is ellenőrzi.
A proxy felülírja a kliens credentialheadereit a binding értékeivel, kizárólag a
pontos engedélyezett kéréshez; redirect vagy más metódus nem örökli a credentialt.
A secret nem kerül argvba, template-be vagy jobopcióba. Ha a target visszatükrözi,
a binding a nyers scanner-evidence mentése előtt is redaktálja. Lejárat és
identitáseltérés blokkolás, nincs anonim fallback vagy automatikus refresh.

## Kontraktus és bekötés

```python
from redjohn.tools.hunt.nuclei import NucleiAdapter, NucleiLock, NucleiOptions

adapter = NucleiAdapter(
    sandbox_session,
    NucleiLock.from_mapping(operator_reviewed_lock),
    request_admission=lambda count: store.consume_requests(policy, count),
    evidence_sink=lambda raw: store.evidence_put(
        policy.engagement_id, raw, job_id=job_id, kind="nuclei_raw",
    ),
)
result = await adapter.run(
    observed_url, options=NucleiOptions(timeout_seconds=60), policy=policy,
)
```

A scheduler ResourceGovernor-foglalása az adapter hívása előtt történik. A közvetlen legacy callbackes módban a `request_admission` az előkészített templates maximális kérésdarabszámát a tartós globális keretből **scan előtt** foglalja; elutasítása nem indít hálózati scant. Unknown outcome/timeout után a lefoglalt keret nem tér vissza automatikusan. A scheduler által indított proxyos módban ez a pre-reservation callback nincs bekötve: a proxy minden tényleges kérés előtt a tartós keretből von le, ezért nincs dupla elszámolás vagy budgeten túli rejtett kérés. Az `evidence_sink` a bounded nyers kimenetet az access-controlled evidence-tárba írja; a publikus eredmény referenciát és diagnosztikahash-t ad, nem nyers stderr/stdoutot. Storagehiba nem eredményez megerősítést.

A legacy `hunt` tool kontextusa: `assessment_policy`, `resource_governor`, `sandbox_session`, `nuclei_lock`. Ezekhez a tool nem fogad LLM által kitalált shell/config/output kapcsolókat. A `hunt_argv("cve", ...)` lock nélkül hibát ad: a régi, globális templates kiválasztás szándékosan megszűnt.

Lock-séma (a SHA értékeket a tényleges, ellenőrzött fájlokból kell számolni):

```json
{
  "binary": {
    "path": "/absolute/resolved/existing/nuclei",
    "version": "3.x.y",
    "sha256": "actual_binary_sha256",
    "source": "immutable_verified_install_source",
    "license": "verified_binary_license_reference"
  },
  "bundle": {
    "root": "/absolute/reviewed/bundle",
    "version": "immutable_bundle_commit_or_release",
    "source": "immutable_verified_bundle_source",
    "license": "verified_bundle_and_auxiliary_license_references",
    "sha256": "bundle_digest(files)",
    "files": {"reviewed.yaml": "actual_file_sha256"},
    "templates": [{
      "path": "reviewed.yaml", "id": "exact-template-id",
      "profiles": ["isolated-lab"], "effect": "read-only", "protocol": "http"
    }]
  }
}
```

A `bundle_digest(files)` a rendezett, kompakt JSON file-name→SHA256 map SHA256 lenyomata. A segédfájlokat is fel kell venni a mapbe; a jelenlegi statikus subset nem használ külső payloadfájlt. Az aláírás nem helyettesíti a hatásreviewt, és a RedJohn nem ír alá generált templates-fájlt.

## Eredmény és lefedettség

A `execution_status`, `coverage_status` és a finding `finding_status` külön mező. Scannerhit kizárólag `candidate`; nincs automatikus confirmed/RCE/CVE-érintettség állítás. Hibás/truncated JSON, toolhiba, timeout, cancel és hiányzó tool nem jelent „nincs sérülékenység”. A parse-olható részleges candidate megőrizhető a részleges evidence mellett.

A korábbi `requests`-statisztika önmagában továbbra sem negatív bizonyíték. A `response_observations` host callback az explicit proxy **teljes, bounded, framing-ellenőrzött** upstreamválaszait adja; a normalizer a template-ekből kiszámolt összes tényleges URL-t és darabszámot összeveti ezzel. Exit0 + üres stdout kizárólag akkor `succeeded/completed/no_finding_observed=true`, ha minden elvárt kéréshez van teljes 2xx-válasz, és nincs parser-, timeout-, cancel-, output- vagy proxyhiba. 401/403/429/5xx blokkolt/inconclusive eredmény; részleges vagy hiányzó capture nem negatív. Az eredmény HTTP-státuszlistát is tartalmaz. A közös rate-limit/cooldown kezelést a scheduler adapter callbackjei végzik, a `-rl` ennek további engine-oldali korlátja.

## Ellenőrzött referenciák és licenchatár

- Hivatalos [v3.11.1 release](https://github.com/projectdiscovery/nuclei/releases/tag/v3.11.1), [GitHub release API](https://api.github.com/repos/projectdiscovery/nuclei/releases/tags/v3.11.1).
- Az ellenőrzött commit [CLI flagkontraktusa](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/cmd/nuclei/main.go): `-proxy`, `-proxy-internal`, no-update/interaction/redirect/stdio/output opciók. A tényleges v3.11.1 motorral ezek kompatibilitása live tesztben is igazolt.
- Az exact commit [MIT licence](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/LICENSE.md), SHA256 `5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c`.
- A [hivatalos checksumfájl](https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_checksums.txt) SHA256-je be van égetve az installerbe. Az installer Darwin/Linux arm64/amd64 archívumpinjei ellenőrzött upstream assetekből származnak; a tényleges integráció itt csak Darwin arm64-en futott.

Nem került átvételre Strix/HexStrike komponens, exploit vagy upstream template. A marker nem CVE vagy RCE reprodukció. A 3.11.1 legfrissebb-kiadás ellenőrzése nem teljes upstream sérülékenységaudit.

## Reprodukálható ellenőrzés

A `RedJohn/` forráskönyvtárból, meglévő engine nélkül az explicit installer egyszer futtatható:

```bash
python3 scripts/install-nuclei-pinned.py
python3 scripts/create-nuclei-fixture-lock.py
../.venv/bin/python -m pytest -q tests/test_nuclei_live.py -rs
../.venv/bin/python -m pytest -q tests/test_hunt_nuclei.py tests/test_native_fixture_session.py tests/test_nuclei_installer.py
```

Az installer sosem fut a tesztek vagy a scheduler mellékhatásaként. Már létező destinationt – versenyhelyzetben megjelenő üres könyvtárat is – atomikus `mkdir`/exclusive-create védi; sérült download és eltérő licencdigest nem települ. Írási hiba után részlegesen létrejött új installkönyvtár maradhat; a következő futás azt is megőrzi és visszautasítja a felülírást, az operátor külön ellenőrizheti/átnevezheti. A fixture-lock controller által felülvizsgált tartalmi lock, hordozáskor az abszolút útvonalakat a generáló script állítja elő.

A `tests/test_nuclei_live.py` **valódi engine**: HTTP marker → fixed control; HTTPS marker → fixed control; self-signed és hostname-mismatch TLS-elutasítás; tényleges 401/403/429 válaszok. A `tests/test_nuclei_installer.py` **mock download / integritás-fault teszt**, nem valódi telepítés vagy scan. A `test_hunt_nuclei` és `test_native_fixture_session` fake scanneres kontraktus-/processzteszt. A kategóriák nem helyettesítik egymást. A saját Nuclei-tesztcsoport végleges futása **66 passed / 14.49 s** (7 valódi engine E2E teszteset, 6 mock download installer teszt, 53 kontraktus/native-process teszt); Ruff és a három módosított source modul mypy-ellenőrzése is sikeres. A HTTP live időmérések a [nuclei-live-measurements.json](nuclei-live-measurements.json) fájlban vannak, a scheduleres browser → inventory → HTTPS Nuclei E2E a közös átadás külön mérési eredménye.

A fenti 66 teszt a korábbi snapshot eredménye. Az új
`tests/test_nuclei_auth_live.py` valódi motort és saját HTTPS auth-fixture-t használ;
`tests/test_assessment_auth_replay.py` vault/binding unit- és negatív kontrollokat
ad. A Linux `tests/test_remote_authenticated_pipeline.py` külön kernelhatáros
browser–inventory–Nuclei–restart E2E, kötelező dependency módban is futtatható.

## Belső natív fixture-session

`redjohn.assessment.native_session.NativeFixtureSession(policy, workspace, lock)`
az új, modellen kívüli CLI Nuclei transportja. A `local-fixture` ág
`isolated-lab` + literal loopback policyt igényel; az `enforced` remote ág csak
élő, kernelből attesztált LinuxEgressBoundary kötése után indíthat workert.
Az osztály nem publikus shelltool: kizárólag az ellenőrzött supervisor/cancel
forrást és a lockból rekonstruált teljes argv/config kontraktust engedi.
Tetszőleges Python-forrás, shell, más bináris, más target és nem lockolt fájl
olvasása tiltott.

A Python supervisor `-I -S` izolált interpreterrel, providerkulcsok nélküli környezetben, 0700 munkakönyvtárban fut. A külső capture is külön byte-bounded; timeout/cancel/finally lezárja a supervisor processgroupot, és szükség esetén a saját tokenhez tartozó scanner-child processgroupot. A fájlolvasás allowlistes, template max64 KiB, bináris default256 MiB, konfigurálható felső korláttal. Legfeljebb 2 belső workerreservation lehet; a közös ResourceGovernor további admissiont végez. A remote namespace határát a külön egress-komponens adja; ez nem hard RAM-limit vagy teljes hostfirewall.

Külön teszt: `python -m pytest -q tests/test_native_fixture_session.py`. A scanner itt szándékosan fake; az interpreter, streaming, outputlimit, timeout/cancel, engedélyellenőrzés és processcleanup valódi subprocess viselkedés. A valódi Nuclei-engine ellenőrzés a külön `tests/test_nuclei_live.py` csoportban ténylegesen lefutott.

A natív csoport első futása **7 passed / 3.98 s**. Külön tényleges PID/processgroup ellenőrzés a `nuclei-native-measurements.json`: a supervisor és a fake scanner processgroupja cancel után hiányzik, 0 workerreservation, 0 marker és 0 ideiglenes worker-directory maradt. A fájl a mért cleanup időt tartalmazza; ez explicit mock scannerrel végzett valódi process-lifecycle mérés, nem Nuclei scan.
