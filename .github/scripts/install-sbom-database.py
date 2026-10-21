#!/usr/bin/env python3
"""CI-only two-advisory DB; no official aggregate/feed-coverage claim.

Downloads are hash/size pinned. The unmodified upstream module go.mod/go.sum
and Go checksum database authenticate transitive build dependencies. Native
matching is tested separately under deny-all network and the owned memory fence.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / 'redjohn/assessment/notices/trivy-sbom-provenance.json'
REV = 'cbebf2ecd6df42d36463844a45e689afee51c70f'
ARCHIVE_SHA = '801aff582c124af4969b69d5f574a8b81f5ec6e84d3938bfa169bffa596ee483'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fetch(url, sha, maximum, exact=None):
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.url.startswith(('https://raw.githubusercontent.com/', 'https://codeload.github.com/')):
            raise ValueError('sbom_fixture_redirect_denied')
        raw = response.read(maximum + 1)
    if len(raw) > maximum or digest(raw) != sha or (exact is not None and len(raw) != exact):
        raise ValueError('sbom_fixture_source_integrity_mismatch')
    return raw


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('explicit_hosted_ci_fixture_builder_only')
    pin = json.loads(PIN.read_text())
    destination = ROOT / '.tools/trivy-sbom-fixture'
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    out = ROOT / 'artifacts/sbom-build'
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    archives = fetch('https://codeload.github.com/aquasecurity/trivy-db/tar.gz/' + REV,
                     ARCHIVE_SHA, 4 * 1024**2, 3042007)
    with tempfile.TemporaryDirectory(prefix='sbom-build-', dir=os.environ['RUNNER_TEMP']) as temporary:
        build = Path(temporary)
        archive = build / 'builder.tar.gz'
        archive.write_bytes(archives)
        prefix = 'trivy-db-' + REV
        expanded = 0
        with tarfile.open(archive, 'r:gz') as tar:
            members = tar.getmembers()
            if len(members) > 12000:
                raise ValueError('sbom_fixture_archive_count')
            for member in members:
                name = Path(member.name)
                if (name.is_absolute() or '..' in name.parts or name.parts[0] != prefix
                    or '\\' in member.name or not (member.isfile() or member.isdir())
                    or member.size > 40 * 1024**2):
                    raise ValueError('sbom_fixture_archive_type_or_path')
                expanded += member.size
                if expanded > 48 * 1024**2:
                    raise ValueError('sbom_fixture_expanded_budget')
                target = build / name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(member).read())
        module = build / prefix
        reviewed = pin['database_library']
        for name, sha in [('LICENSE', reviewed['license_sha256']), ('NOTICE', reviewed['notice_sha256'])]:
            raw = (module / name).read_bytes()
            if digest(raw) != sha:
                raise ValueError('sbom_fixture_builder_license_mismatch')
            (destination / ('builder-' + name)).write_bytes(raw)
        inputs = build / 'inputs'
        # Empty optional CocoaPods metadata is local fixture input, never fetched.
        (inputs / 'cocoapods-specs/Specs').mkdir(parents=True)
        ghsa = pin['reviewed_advisory_source']
        terms = fetch(ghsa['license_url'], ghsa['license_sha256'], 65536, ghsa['license_bytes'])
        (destination / 'ghsa-LICENSE.md').write_bytes(terms)
        for item in ghsa['fixtures']:
            raw = fetch(item['url'], item['sha256'], 65536, item['bytes'])
            relative = item['url'].split(ghsa['revision'] + '/', 1)[1]
            target = inputs / 'ghsa' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        command = module / 'cmd/redjohn-fixture'
        command.mkdir()
        (command / 'main.go').write_bytes((ROOT / '.github/fixtures/trivy-sbom/main.go').read_bytes())
        with (out / 'builder.log').open('wb') as log:
            subprocess.run(['go', 'run', '-mod=readonly', './cmd/redjohn-fixture', str(inputs), str(destination)],
                           cwd=module, check=True, timeout=420, stdout=log, stderr=subprocess.STDOUT)
        for name in ('go.mod', 'go.sum'):
            (out / (name.replace('.', '-') + '.txt')).write_bytes((module / name).read_bytes())
    now = datetime.now(UTC)
    metadata = {'Version': 2, 'UpdatedAt': now.isoformat(), 'NextUpdate': (now + timedelta(hours=6)).isoformat()}
    raw_metadata = json.dumps(metadata).encode()
    (destination / 'metadata.json').write_bytes(raw_metadata)
    raw_db = (destination / 'trivy.db').read_bytes()
    if len(raw_db) > 8 * 1024**2:
        raise ValueError('sbom_fixture_database_byte_budget')
    provenance = {
        'format': 'redjohn-trivy-db-controlled-fixture-v1', 'publisher': 'redjohn-local-controlled-fixture',
        'oci_reference': '', 'builder_revision': REV, 'database_sha256': digest(raw_db),
        'database_bytes': len(raw_db), 'metadata_sha256': digest(raw_metadata), 'acquired_at': now.isoformat(),
        'license_review': {'engine_license_sha256': reviewed['license_sha256'],
                          'database_builder_license_sha256': reviewed['license_sha256'],
                          'database_builder_notice_sha256': reviewed['notice_sha256'],
                          'operator_terms_reviewed': True},
        'data_sources': [{'id': 'ghsa', 'url': ghsa['repository'], 'terms_url': ghsa['license_url'],
                          'terms_file': 'ghsa-LICENSE.md', 'terms_sha256': digest(terms)}]}
    raw_provenance = json.dumps(provenance).encode()
    (destination / 'provenance.json').write_bytes(raw_provenance)
    config = {'root': str(destination), 'database_sha256': digest(raw_db), 'database_bytes': len(raw_db),
              'metadata_sha256': digest(raw_metadata), 'provenance_file': str(destination / 'provenance.json'),
              'provenance_sha256': digest(raw_provenance), 'origin': 'controlled_ghsa_fixture'}
    (destination / 'configuration.json').write_text(json.dumps(config, indent=2))
    receipt = {**config, 'builder_archive_sha256': ARCHIVE_SHA, 'advisory_revision': ghsa['revision'],
               'advisories': ghsa['fixtures'], 'official_aggregate_database': False,
               'build_time_is_not_advisory_freshness': True, 'native_matching_verified_by_separate_e2e': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    (ROOT / 'artifacts/tool-receipts/trivy-sbom-fixture.json').write_text(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
