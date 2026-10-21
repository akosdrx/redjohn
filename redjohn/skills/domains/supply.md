---
name: supply
description: When a version, a lockfile, or a dependency is a finding. A CVE id next to a banner is not one.
---

# Supply

`lookup_cve` is a lead generator. File a vulnerability when this target is actually in the affected range and you either reproduced the bug or you are filing a dependency report for a vulnerable component that is resolved into the build. A banner, a `package.json` range, or an NVD hit on a product you did not confirm is correlation. Say that, and do not call it verified exploitation.

## Version confidence

Highest: you executed the component or read its version from a file the app serves. Next: a lockfile or a runtime manifest you retrieved. Lowest: a guessed product from a path or a header. Only the first two justify `create_dependency_report`. Record the file or the request you used.

A fixed version newer than what is installed is the finding's point. If the installed version is outside the affected range, rule it out in one sentence and move on.

## Lockfiles and installs

The range in `package.json` is not what got installed. Read the lockfile or the image. Dependency confusion and typosquats matter when the name resolves to a registry the build will actually fetch, and you can show the resolution. An abandoned dependency is context until there is a vulnerable version in the tree or a missing integrity check on an update the app applies.

## Update and build channels

An update URL, a container base, or a CI job that pulls floating tags (`latest`, an unpinned action) is a finding when you show the artifact is not pinned or not verified and an attacker who can publish there changes what this app runs. A suggestion to pin, with no such path, is hardening.

**npx and friends.** `npx`, `npm exec`, `bunx`, and `dlx` can run a package whose name is not the binary the user thinks they invoked, especially when the spec is a missing local bin that falls through to the registry. Confirm the spec, the registry response, and that this repo's script or docs send a developer through it.

## Patch diff

A commit that fixes a crash or adds a check is a place to look, not a zero-day writeup. Reproduce the old behavior on the version in scope, or describe the unfixed path in the code you have. Novelty (no public CVE) changes disclosure handling; it does not lower the proof bar.
