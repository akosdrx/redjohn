# RedJohn kontrollált helyi reproducer

A `redjohn.assessment.reproducer.SafeReproducerGenerator` determinisztikus, típusos helyi regressziós terveket készít. Az `AIExploitGenerator` kompatibilitási alias ugyanarra a megvalósításra mutat. A modul nem hajt végre generált kódot, nem tölt le exploitot és nem ad távoli shellt.

Támogatott két állítás:

- Azonos engedélyezett helyi fixture URL-en egy megfigyelt hibás/hiányzó `X-Content-Type-Options: nosniff` vagy a fixture `Content-Security-Policy: default-src 'self'` fejlécének megerősítése egy külön, javított deployment-kontrollal.
- `X-RedJohn-Fixture: initial` → `fixed` ártalmatlan marker-kontroll. Ez `routing_fixture_marker`, és siker esetén is csak `candidate`: nem bizonyít command injectiont, SSTI-t vagy RCE-t.

A tervhez observed candidate, konkrét candidate/fixture/asset/actor reference, eredeti evidence reference és pontos URL kell. A megadott evidence hozzáférését a meglévő, engagementhez kötött reader ellenőrzi; a teljes, bounded bizonyíték URL/actor/status/header kontextusának egyeznie kell. A modul csak `isolated-lab` profilban, literal loopback URL-en, anonim actorral működik. Hitelesített replay hiányában nem hagyja el az authot csendben: blokkol.

```python
from redjohn.assessment.reproducer import ReproducerRequest, SafeReproducerGenerator

reproducer = SafeReproducerGenerator(
    policy, caller=policy.owner_id, governor=runtime.governor,
    evidence_reader=lambda ref: store.evidence_get(policy.engagement_id, ref),
    evidence_sink=lambda value: store.evidence_put(
        policy.engagement_id, value, kind="safe_reproducer_observation",
    ),
    request_admission=lambda count: store.consume_requests(policy, count),
)
plan = reproducer.generate(ReproducerRequest(
    candidate_ref="existing-candidate", fixture_ref="local-fixture:headers",
    asset_ref="fixture-http-asset", actor_ref="anonymous",
    url=exact_observed_fixture_url, evidence_refs=(observed_http_evidence_ref,),
))
before = await reproducer.observe(plan, phase="candidate", deployment_ref="fixture-before-1")
# A fixture tulajdonosa itt kapcsol a tényleges, javított változatra.
control = await reproducer.observe(plan, phase="fixed_control", deployment_ref="fixture-fixed-2")
result = reproducer.validate_pair(plan, before.observation_ref, control.observation_ref)
source = reproducer.regression_source(plan)  # konstans unittest-szöveg; nem futtatjuk exec-kel
```

A hálózati megfigyelés véges GET-et használ 5 s abszolút timeouttal, 64 KiB kitömörített bodylimittel, max 1 KiB kiválasztott fejléccel, tiltott redirecttel és kikapcsolt környezeti proxy-/credential-használattal. Cookie-t és authot nem küld, nem rögzít és nem exportál. A client/stream kontextus és a közös erőforráslease siker, hiba és cancel esetén is lezáródik. Minden kérés a tartós globális keretből foglalódik. 401/403/429/503/redirect blokkolt eredmény; túl nagy/hibás output inconclusive. Nincs automatikus retry.

Csak a modul saját élő megfigyelés-referenciái, azonos változatlan terv, helyes before/fixed_control sorrend és eltérő deployment reference alapján lehet párt validálni. Két azonos deployment vagy továbbra is hiányzó kontrollfejléc nem eredményez megerősítést. Sikeres helyi fejléc-kontroll `confirmed_weakness`; `confirmed_impact`, RCE és dinamikus CVE nincs. A történeti finding adatbázisbeli átminősítése külön, a hívó által végzendő művelet, nem történik láthatatlanul.

A tervállapot default 32/maximum 128 elem, megfigyelés default 64/maximum 256 elem; a párhuzamos, még folyamatban levő megfigyelések is foglalnak helyet. A bizonyíték a meglévő védett store-ba íródik, nem LRU-cache-be. Storagehiba nem hoz létre validálható observationt. Az export statikus unittest forrás, csak rögzített loopback URL-lel, no-redirect HTTP clienttel, véges timeouttal és header assertionnel. A modul és a teszt nem futtat generált kódot; OS-sandboxolt általános kódvégrehajtást nem állítunk.

Az eredeti RCE ismétléséhez nincs eredeti fixture/kérés/mechanizmus: minden eredményben `original_rce_status=not_reproduced_missing_fixture` szerepel.

## Tényleges ellenőrzés

```bash
python -m pytest -q -s tests/test_assessment_reproducer.py
ruff check redjohn/assessment/reproducer.py tests/test_assessment_reproducer.py
python -m mypy redjohn/assessment/reproducer.py --follow-imports=silent
```

A megvalósításkor a meglévő `FixtureServer` ellen **14 teszt** ment át (a külön natív supervisor csoporttal együtt **21 passed / 11.53 s**). A külön mért pozitív + fixed-control fejlécellenőrzés **0.10903 s**, **3 valódi HTTP-kérés**, **3 tartós request charge**, **1 confirmed_weakness**, **0 confirmed_impact**, **0 modellhívás**, **0 generáltkód-végrehajtás**. Ez kisméretű helyi mérés, nem általános scanner- vagy RCE-benchmark. A mock Nuclei tesztcsoporttól külön fájlban található.
