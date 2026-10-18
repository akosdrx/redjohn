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

Unimplemented and deliberately deferred capabilities in the generated matrix
remain distinct from installed engines. The remaining source/network/CMS/cloud/
Kubernetes additions need their own verified pins and notices before release.
