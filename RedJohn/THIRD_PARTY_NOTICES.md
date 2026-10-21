# RedJohn distribution provenance

RedJohn retains its existing package name, branding and Apache-2.0 license
metadata. `LICENSE` contains the corresponding Apache Software Foundation
license text, with its source URL/hash recorded in `docs/license-provenance.json`.
This notice does not change third-party licenses or attribute ownership of
third-party work to RedJohn.

The deterministic assessment implementation uses RedJohn's existing package,
SDK, persistent SQLite store and scheduler. Strix and HexStrike references are
identified by checked commit and license in `../docs/third-party-references.json`;
they do not replace RedJohn or introduce another embedded orchestrator. That
reference record describes this implementation's reuse, not a retrospective
claim about authorship of every pre-existing project file.

Optional scanner engines are not embedded in the Python source tree or wheel.
Explicit installers place selected, verified engines in ignored `.tools/`
directories and retain upstream license/provenance receipts there. Engine
version/checksum/source/license and the license of rules, template bundles or
advisory datasets are separate records. Installing an engine does not imply
rights to redistribute every external rule/feed or enable a paid provider.

The current executable adapters and their source/version/license boundaries
are documented in `../docs/redjohn-capabilities.md` and each adapter's pinned
installer. The reviewed Nuclei fixture templates are project-owned; the full
upstream template catalog is not downloaded automatically. Selected TInjA
execution carries its required upstream license under
`redjohn/assessment/notices/TInjA-LICENSE.txt`.

Python, frontend and Go dependencies retain their own upstream licenses.
The built Viewer contains its frontend dependencies and the native Go TUI is
included in the platform wheel; their exact resolved versions are recorded by
the dependency lockfiles and commit-bound build evidence. Any release bundle
must preserve applicable dependency notices; a successful unit test or engine
receipt alone is not a complete release-distribution license audit.

The additional reviewed integrations retain separate source/license records:

| Component | Reviewed identity | Scope |
| --- | --- | --- |
| Naabu / dnsx | 2.6.1 / 1.3.1, MIT; exact commits, archive and license hashes in `scripts/network-scanner-pins.json` | Explicit optional external engines; no default discovery launch. |
| Nmap | 7.992, source `0ee561663c1d7d2d4e708cd414dccfd3d9df30d9`, NPSL 0.95 | Explicit operator-installed engine / owned CI fixture build only. Product, commercial, OEM or SaaS rights are not granted by this notice. RedJohn supplies its own minimal probe profile. See `../docs/redjohn-nmap-service-profile.md`. |
| graphql-core | Exact optional parser dependency 3.3.0, MIT | No upstream source is copied; installing the explicit GraphQL extra retains the dependency's license. See `docs/redjohn-graphql-workflows.md`. |
| Prowler | 5.45.0, `bffc8844c1c9a3666e37a2ada4ee05f62e1446b0`, Apache-2.0 | Input-manifest preparation only; the full pinned Python dependency snapshot and live account authority remain unavailable. No engine audit is claimed. |
| kube-bench | 0.16.0, `5c6c22d51b926020e7414e1f1e051851d1a2feff`, Apache-2.0 | Explicit optional download; only a fixed isolated version command is supported by preparation. Benchmark YAML execution and live node/cluster authority are not granted. |

Cloud/Kubernetes reviewed primary-source/license hashes and native release pins
are recorded in `redjohn/assessment/notices/preparation-provenance.json`.
Preparation is not live audit coverage. Unimplemented and deliberately deferred
capabilities in the generated matrix remain distinct from installed engines.
WPScan's full dependency and commercial-license review remains unfinished; no
WPScan runtime or redistribution permission is implied by this candidate.
