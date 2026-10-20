#!/usr/bin/env python3
"""Reject omitted/mocked/skipped artifact E2Es and missing actual owner receipts."""
import argparse
import hashlib
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from ci import OUT, identity

EXPECTED = {
    'test_wpscan_observe_live.py': {
        'test_real_offline_component_observation_and_durable_restart[positive]',
        'test_real_offline_component_observation_and_durable_restart[generic]',
        'test_real_offline_component_observation_and_durable_restart[external-dtd]',
        'test_real_native_health_then_durable_cancel_prevents_observation'},
    'test_trivy_sbom_live.py': {
        'test_real_sbom_public_scheduler_matching_and_restart[pypi-positive]',
        'test_real_sbom_public_scheduler_matching_and_restart[pypi-fixed]',
        'test_real_sbom_public_scheduler_matching_and_restart[npm-positive]',
        'test_real_sbom_public_scheduler_matching_and_restart[npm-fixed]',
        'test_real_sbom_cancel_after_native_health_prevents_scan',
        'test_actual_sbom_invalid_database_is_blocked_not_a_negative[missing]',
        'test_actual_sbom_invalid_database_is_blocked_not_a_negative[digest]'},
}


def validate(junit, receipts):
    suites = {name: {} for name in EXPECTED}
    failures = []
    for case in ET.parse(junit).getroot().iter('testcase'):
        name = Path(case.get('file', '')).name
        if name not in EXPECTED:
            continue
        test = case.get('name')
        props = {x.get('name'): x.get('value') for x in case.findall('properties/property')}
        if (test not in EXPECTED[name] or test in suites[name]
            or any(case.find(tag) is not None for tag in ('skipped', 'failure', 'error'))
            or props.get('evidence_kind') != 'real_integration'
            or set(props.get('required_runner_capabilities', '').split(',')) != {'namespace_available', 'cgroup_available'}):
            failures.append('invalid_native_case:' + str(test))
        suites[name][test] = {'passed': not any(case.find(tag) is not None for tag in ('skipped', 'failure', 'error'))}
    found = {}
    for path in sorted(receipts.glob('artifact-*.json')):
        if path.stat().st_size > 65536:
            raise ValueError('artifact_owner_receipt_byte_budget')
        raw = path.read_bytes()
        value = json.loads(raw)
        nodeid = value['nodeid']
        name, test = Path(nodeid.split('::')[0]).name, nodeid.split('::', 1)[1]
        if name not in EXPECTED or test not in EXPECTED[name] or (name, test) in found:
            failures.append('unexpected_or_duplicate_owner_receipt')
            continue
        kernel = value['kernel']
        memory = kernel['os_memory']
        if (kernel.get('process_cleanup_verified') is not True
            or memory.get('owner_namespace', {}).get('verified') is not True
            or memory.get('oom_kills') != 0 or memory.get('memory_max_bytes') != 2048 * 1024**2
            or type(memory.get('memory_peak_bytes')) is not int or memory['memory_peak_bytes'] < 1):
            failures.append('invalid_owner_fence:' + test)
        found[name, test] = {'receipt': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                             'memory_peak_bytes': memory.get('memory_peak_bytes'),
                             'memory_max_bytes': memory.get('memory_max_bytes')}
    for name, tests in EXPECTED.items():
        if set(suites[name]) != tests or any((name, test) not in found for test in tests):
            failures.append('incomplete_artifact_suite:' + name)
        for test in suites[name]:
            suites[name][test].update(found.get((name, test), {}))
    return {'suites': suites, 'blockers': failures, 'success': not failures,
            'evidence_kind': 'real_native_engines_controlled_fixtures',
            'full_wordpress_vulnerability_audit': False, 'official_aggregate_advisory_coverage': False}


RECOVERY_CASE = 'test_actual_orphan_is_killed_before_crashed_owner_capacity_is_reclaimed'


def validate_recovery(root):
    results = []
    for repeat in (1, 2, 3):
        cases = list(ET.parse(root / f'recovery-{repeat}.junit.xml').getroot().iter('testcase'))
        if (len(cases) != 1 or cases[0].get('name') != RECOVERY_CASE
            or Path(cases[0].get('file', '')).name != 'test_os_memory_live.py'
            or any(cases[0].find(tag) is not None for tag in ('error', 'failure', 'skipped'))):
            raise ValueError('recovery_actual_case_missing_or_failed')
        props = {x.get('name'): x.get('value') for x in cases[0].findall('properties/property')}
        if props.get('evidence_kind') != 'real_integration':
            raise ValueError('recovery_real_evidence_required')
        path = root / f'recovery-{repeat}' / 'owner-crash-recovery.json'
        if path.stat().st_size > 65536:
            raise ValueError('recovery_receipt_byte_budget')
        data = json.loads(path.read_text())
        memory = data['os_memory']
        if (data.get('actual_owner_exit_verified') is not True
            or data.get('orphan_survived_owner_exit') is not True
            or data.get('orphan_stopped') is not True
            or data['before']['lost_owners'] != 1 or data['after']['active'] != {}
            or memory.get('enforced') is not True
            or memory.get('memory_max_bytes') != 128 * 1024**2
            or memory.get('oom_kills') != 0
            or memory.get('owner_namespace', {}).get('verified') is not True):
            raise ValueError('recovery_actual_owner_and_orphan_proof_required')
        results.append({'repeat': repeat, 'test': RECOVERY_CASE,
                        'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'memory_max_bytes': memory['memory_max_bytes'],
                        'memory_peak_bytes': memory.get('memory_peak_bytes')})
    return {'passed_executions': 3, 'results': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--final-artifact', action='store_true')
    args = parser.parse_args()
    meta = identity()
    try:
        result = {**meta, **validate(OUT / 'integration.junit.xml', Path(os.environ['REDJOHN_OS_MEMORY_MEASUREMENTS']))}
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError):
        result = {**meta, 'suites': {}, 'success': False, 'blockers': ['missing_or_invalid_native_evidence']}
    if args.final_artifact:
        result.update(validation_scope='offline_artifact_e2e', full_project_validated=False)
        for name in ('python-install', 'pip-check', 'artifact-ci-contracts', 'artifact-linux-dependencies',
                     'artifact-trivy-install', 'artifact-database-install', 'artifact-runtime-install',
                     'linux-setup', 'sandbox-setup', 'python-integration', 'sandbox-cleanup',
                     'memory-recovery-1', 'memory-recovery-2', 'memory-recovery-3'):
            try:
                command = json.loads((OUT / (name + '.json')).read_text())
                if command['commit_sha'] != meta['commit_sha'] or command['exit_code'] != 0 or command['leaked_descendant_pids_before_cleanup']:
                    raise ValueError('failed_command')
            except (OSError, ValueError, TypeError, KeyError):
                result['blockers'].append('missing_or_failed_command:' + name)
        for name, key in (('capabilities.json', 'available'), ('apparmor-cleanup.json', 'success'),
                          ('cgroup-cleanup.json', 'removed')):
            try:
                value = json.loads((OUT / name).read_text())
                if value.get(key) is not True or value.get('leaked_processes'):
                    raise ValueError('unverified_cleanup_or_capability')
            except (OSError, ValueError, TypeError, KeyError):
                result['blockers'].append('missing_or_invalid_boundary:' + name)
        try:
            result['owner_recovery'] = validate_recovery(OUT)
        except (OSError, ValueError, KeyError, TypeError, ET.ParseError):
            result['blockers'].append('missing_or_invalid_owner_recovery_proof')
        result['success'] = not result['blockers']
    (OUT / 'artifact-native-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    if args.final_artifact:
        evidence = {str(path.relative_to(OUT)): {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'bytes': path.stat().st_size} for path in sorted(OUT.rglob('*'))
                    if path.is_file() and path.suffix in {'.xml', '.json', '.log', '.txt'}
                    and path.name != 'evidence-index.json'}
        (OUT / 'evidence-index.json').write_text(json.dumps({**meta, 'files': evidence}, indent=2))
    print(json.dumps({'success': result['success'], 'blockers': result['blockers'],
                      'cases': {name: len(rows) for name, rows in result['suites'].items()}}))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
