"""Synthetic CI receipt/JUnit gate contracts, not native integration evidence."""
import importlib.util
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[1] / 'scripts'
SPEC = importlib.util.spec_from_file_location('artifact_test_ci', SCRIPTS / 'ci.py')
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)
SPEC = importlib.util.spec_from_file_location('artifact_evidence', SCRIPTS / 'artifact-evidence.py')
evidence = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {'ci': ci}):
    SPEC.loader.exec_module(evidence)


class ArtifactEvidenceContracts(unittest.TestCase):
    def fixture(self, root):
        suite = ET.Element('testsuite')
        receipts = root / 'receipts'
        receipts.mkdir()
        for number, (filename, tests) in enumerate(evidence.EXPECTED.items()):
            for index, test in enumerate(sorted(tests)):
                case = ET.SubElement(suite, 'testcase', file='tests/' + filename, name=test)
                props = ET.SubElement(case, 'properties')
                ET.SubElement(props, 'property', name='evidence_kind', value='real_integration')
                ET.SubElement(props, 'property', name='required_runner_capabilities', value='cgroup_available,namespace_available')
                record = {'nodeid': 'tests/' + filename + '::' + test,
                          'kernel': {'process_cleanup_verified': True, 'os_memory': {
                              'owner_namespace': {'verified': True}, 'oom_kills': 0,
                              'memory_max_bytes': 2048 * 1024**2, 'memory_peak_bytes': 12345}}}
                (receipts / f'artifact-{number}-{index}.json').write_text(json.dumps(record))
        junit = root / 'suite.xml'
        ET.ElementTree(suite).write(junit)
        return suite, junit, receipts

    def test_complete_synthetic_gate_contract_does_not_claim_full_audits(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, junit, receipts = self.fixture(Path(temporary))
            value = evidence.validate(junit, receipts)
            self.assertTrue(value['success'])
            self.assertFalse(value['full_wordpress_vulnerability_audit'])
            self.assertFalse(value['official_aggregate_advisory_coverage'])
            self.assertEqual(sum(len(tests) for tests in value['suites'].values()), 11)

    def test_missing_mocked_skipped_unattested_or_oom_results_are_rejected(self):
        for defect in ('omitted', 'duplicate', 'skip', 'mock', 'caps', 'receipt', 'owner', 'oom', 'budget'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                suite, junit, receipts = self.fixture(Path(temporary))
                case = suite.find('testcase')
                path = next(receipts.glob('*.json'))
                if defect == 'omitted': suite.remove(case)
                elif defect == 'duplicate': suite.append(case)
                elif defect == 'skip': ET.SubElement(case, 'skipped')
                elif defect == 'mock': case.find('properties/property').set('value', 'mock_contract')
                elif defect == 'caps': case.findall('properties/property')[1].set('value', 'namespace_available')
                elif defect == 'receipt': path.unlink()
                else:
                    record = json.loads(path.read_text())
                    memory = record['kernel']['os_memory']
                    if defect == 'owner': memory['owner_namespace']['verified'] = False
                    elif defect == 'oom': memory['oom_kills'] = 1
                    else: memory['memory_max_bytes'] = 0
                    path.write_text(json.dumps(record))
                ET.ElementTree(suite).write(junit)
                self.assertFalse(evidence.validate(junit, receipts)['success'])


class OwnerRecoveryEvidenceContracts(unittest.TestCase):
    def fixture(self, root):
        for repeat in (1, 2, 3):
            suite = ET.Element('testsuite')
            case = ET.SubElement(suite, 'testcase', file='tests/test_os_memory_live.py', name=evidence.RECOVERY_CASE)
            props = ET.SubElement(case, 'properties')
            ET.SubElement(props, 'property', name='evidence_kind', value='real_integration')
            ET.ElementTree(suite).write(root / f'recovery-{repeat}.junit.xml')
            folder = root / f'recovery-{repeat}'
            folder.mkdir()
            value = {'actual_owner_exit_verified': True, 'orphan_survived_owner_exit': True,
                     'orphan_stopped': True, 'before': {'lost_owners': 1}, 'after': {'active': {}},
                     'os_memory': {'enforced': True, 'memory_max_bytes': 128 * 1024**2,
                                   'oom_kills': 0, 'owner_namespace': {'verified': True},
                                   'memory_peak_bytes': 16000000}}
            (folder / 'owner-crash-recovery.json').write_text(json.dumps(value))

    def test_three_complete_synthetic_gate_receipts_pass_only_the_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            self.assertEqual(evidence.validate_recovery(root)['passed_executions'], 3)

    def test_missing_skipped_live_owner_or_unverified_kernel_cannot_pass(self):
        for defect in ('missing', 'skipped', 'owner', 'orphan', 'kernel', 'capacity'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root)
                path = root / 'recovery-2' / 'owner-crash-recovery.json'
                data = json.loads(path.read_text())
                if defect == 'missing': path.unlink()
                elif defect == 'skipped':
                    tree = ET.parse(root / 'recovery-2.junit.xml')
                    ET.SubElement(tree.getroot().find('testcase'), 'skipped')
                    tree.write(root / 'recovery-2.junit.xml')
                else:
                    if defect == 'owner': data['actual_owner_exit_verified'] = False
                    elif defect == 'orphan': data['orphan_survived_owner_exit'] = False
                    elif defect == 'kernel': data['os_memory']['owner_namespace']['verified'] = False
                    else: data['after']['active'] = {'worker': 1}
                    path.write_text(json.dumps(data))
                with self.assertRaises((ValueError, OSError)):
                    evidence.validate_recovery(root)
