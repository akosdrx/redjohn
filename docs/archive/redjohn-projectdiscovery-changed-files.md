# RedJohn: httpx / Katana / VulnX módosított fájlok

2026-10-18. 68 módosított/új fájl, a megőrzött mérési bizonyítékokkal együtt.

A korábbi Git-átrendezés nem feladattörlés. Nincs destruktív Git-művelet.
A manifestek önmagukra/ciklusokra mutató hash-ei, az ignored managed binárisok és a privát állapotok kizárva.

[Ellenőrzési jelentés](redjohn-projectdiscovery-verification.md) · [SHA-jegyzék](redjohn-projectdiscovery-changed-files.json)

## Forrás, teszt és dokumentáció

| Fájl | Változás |
|---|---|
| [.github/workflows/redjohn-remote-egress.yml](../.github/workflows/redjohn-remote-egress.yml) | modified |
| [README.md](../README.md) | modified |
| [docs/projectdiscovery-adapters.md](projectdiscovery-adapters.md) | added |
| [examples/assessment-projectdiscovery.json](../examples/assessment-projectdiscovery.json) | added |
| [redjohn/assessment/browser_proxy.py](../redjohn/assessment/browser_proxy.py) | modified |
| [redjohn/assessment/cli.py](../redjohn/assessment/cli.py) | modified |
| [redjohn/assessment/discovery_tools.py](../redjohn/assessment/discovery_tools.py) | added |
| [redjohn/assessment/pinned_tools.py](../redjohn/assessment/pinned_tools.py) | added |
| [redjohn/assessment/registry.py](../redjohn/assessment/registry.py) | modified |
| [redjohn/assessment/runtime.py](../redjohn/assessment/runtime.py) | modified |
| [redjohn/assessment/scheduler.py](../redjohn/assessment/scheduler.py) | modified |
| [redjohn/assessment/vulnx.py](../redjohn/assessment/vulnx.py) | added |
| [redjohn/tools/hunt/bounded_worker.py](../redjohn/tools/hunt/bounded_worker.py) | modified |
| [scripts/install-projectdiscovery-pinned.py](../scripts/install-projectdiscovery-pinned.py) | added |
| [scripts/projectdiscovery-pins.json](../scripts/projectdiscovery-pins.json) | added |
| [tests/test_projectdiscovery_contract.py](../tests/test_projectdiscovery_contract.py) | added |
| [tests/test_projectdiscovery_live.py](../tests/test_projectdiscovery_live.py) | added |
| [docs/redjohn-implementation-audit.md](redjohn-implementation-audit.md) | modified |
| [docs/redjohn-projectdiscovery-verification.md](redjohn-projectdiscovery-verification.md) | added |
| [docs/redjohn-requirements.md](redjohn-requirements.md) | modified |
| [docs/third-party-references.json](third-party-references.json) | modified |

## Megőrzött valós mérési bizonyítékok

| Fájl | Változás |
|---|---|
| [docs/measurements/projectdiscovery/cleanup.json](measurements/projectdiscovery/cleanup.json) | added |
| [docs/measurements/projectdiscovery/linux/auth-e2e.json](measurements/projectdiscovery/linux/auth-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/automatic-session-e2e.json](measurements/projectdiscovery/linux/automatic-session-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/binary-integrity.json](measurements/projectdiscovery/linux/binary-integrity.json) | added |
| [docs/measurements/projectdiscovery/linux/browser-token-e2e.json](measurements/projectdiscovery/linux/browser-token-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/chain-loopback.json](measurements/projectdiscovery/linux/chain-loopback.json) | added |
| [docs/measurements/projectdiscovery/linux/chain-remote.json](measurements/projectdiscovery/linux/chain-remote.json) | added |
| [docs/measurements/projectdiscovery/linux/continuous-refresh-e2e.json](measurements/projectdiscovery/linux/continuous-refresh-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/derived.json](measurements/projectdiscovery/linux/derived.json) | added |
| [docs/measurements/projectdiscovery/linux/dns-https.json](measurements/projectdiscovery/linux/dns-https.json) | added |
| [docs/measurements/projectdiscovery/linux/ffuf-e2e-loopback.json](measurements/projectdiscovery/linux/ffuf-e2e-loopback.json) | added |
| [docs/measurements/projectdiscovery/linux/ffuf-e2e-remote.json](measurements/projectdiscovery/linux/ffuf-e2e-remote.json) | added |
| [docs/measurements/projectdiscovery/linux/https-e2e.json](measurements/projectdiscovery/linux/https-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/httpx-install.json](measurements/projectdiscovery/linux/httpx-install.json) | added |
| [docs/measurements/projectdiscovery/linux/katana-install.json](measurements/projectdiscovery/linux/katana-install.json) | added |
| [docs/measurements/projectdiscovery/linux/kernel.txt](measurements/projectdiscovery/linux/kernel.txt) | added |
| [docs/measurements/projectdiscovery/linux/mypy.txt](measurements/projectdiscovery/linux/mypy.txt) | added |
| [docs/measurements/projectdiscovery/linux/nuclei-live.json](measurements/projectdiscovery/linux/nuclei-live.json) | added |
| [docs/measurements/projectdiscovery/linux/post-nuclei-live.json](measurements/projectdiscovery/linux/post-nuclei-live.json) | added |
| [docs/measurements/projectdiscovery/linux/post-refresh-e2e.json](measurements/projectdiscovery/linux/post-refresh-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/processes-after-tests.txt](measurements/projectdiscovery/linux/processes-after-tests.txt) | added |
| [docs/measurements/projectdiscovery/linux/python-packages.txt](measurements/projectdiscovery/linux/python-packages.txt) | added |
| [docs/measurements/projectdiscovery/linux/remote-auth-e2e.json](measurements/projectdiscovery/linux/remote-auth-e2e.json) | added |
| [docs/measurements/projectdiscovery/linux/source-hash-check.txt](measurements/projectdiscovery/linux/source-hash-check.txt) | added |
| [docs/measurements/projectdiscovery/linux/tests.junit.xml](measurements/projectdiscovery/linux/tests.junit.xml) | added |
| [docs/measurements/projectdiscovery/linux/tests.txt](measurements/projectdiscovery/linux/tests.txt) | added |
| [docs/measurements/projectdiscovery/linux/vulnx-install.json](measurements/projectdiscovery/linux/vulnx-install.json) | added |
| [docs/measurements/projectdiscovery/linux/vulnx-public.json](measurements/projectdiscovery/linux/vulnx-public.json) | added |
| [docs/measurements/projectdiscovery/macos/binary-integrity.json](measurements/projectdiscovery/macos/binary-integrity.json) | added |
| [docs/measurements/projectdiscovery/macos/chain-loopback.json](measurements/projectdiscovery/macos/chain-loopback.json) | added |
| [docs/measurements/projectdiscovery/macos/derived.json](measurements/projectdiscovery/macos/derived.json) | added |
| [docs/measurements/projectdiscovery/macos/go-test.txt](measurements/projectdiscovery/macos/go-test.txt) | added |
| [docs/measurements/projectdiscovery/macos/go-vet.txt](measurements/projectdiscovery/macos/go-vet.txt) | added |
| [docs/measurements/projectdiscovery/macos/httpx-install.json](measurements/projectdiscovery/macos/httpx-install.json) | added |
| [docs/measurements/projectdiscovery/macos/katana-install.json](measurements/projectdiscovery/macos/katana-install.json) | added |
| [docs/measurements/projectdiscovery/macos/mypy-final.txt](measurements/projectdiscovery/macos/mypy-final.txt) | added |
| [docs/measurements/projectdiscovery/macos/ruff-final.txt](measurements/projectdiscovery/macos/ruff-final.txt) | added |
| [docs/measurements/projectdiscovery/macos/tests.junit.xml](measurements/projectdiscovery/macos/tests.junit.xml) | added |
| [docs/measurements/projectdiscovery/macos/tests.txt](measurements/projectdiscovery/macos/tests.txt) | added |
| [docs/measurements/projectdiscovery/macos/typescript.txt](measurements/projectdiscovery/macos/typescript.txt) | added |
| [docs/measurements/projectdiscovery/macos/viewer-assets.json](measurements/projectdiscovery/macos/viewer-assets.json) | added |
| [docs/measurements/projectdiscovery/macos/viewer-build.txt](measurements/projectdiscovery/macos/viewer-build.txt) | added |
| [docs/measurements/projectdiscovery/macos/vulnx-install.json](measurements/projectdiscovery/macos/vulnx-install.json) | added |
| [docs/measurements/projectdiscovery/performance-summary.json](measurements/projectdiscovery/performance-summary.json) | added |
| [docs/measurements/projectdiscovery/preservation.json](measurements/projectdiscovery/preservation.json) | added |
| [docs/measurements/projectdiscovery/source-hashes.json](measurements/projectdiscovery/source-hashes.json) | added |
| [docs/measurements/projectdiscovery/test-summary.json](measurements/projectdiscovery/test-summary.json) | added |
