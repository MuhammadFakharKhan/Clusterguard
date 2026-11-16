"""The reused IntentProof library protects the ClusterGuard application."""
import copy
import unittest
from intentproof.assurance import audit_warranty, compare_warranties, verify_recovery

class ClusterGuardContractReuseTests(unittest.TestCase):
    def warranty(self):
        return {
            'warranty_id': 'clusterguard-integrity',
            'steps': [
                {'step_id': 'allocate', 'target': 'fulfillment', 'field': 'recorded', 'value': True, 'requires_approval': True}
            ],
            'postconditions': [{'target': 'fulfillment', 'field': 'recorded', 'equals': True}],
            'unchanged_fields': [{'target': 'consent', 'field': 'version'}],
            'side_effect_candidates': [{'target': 'consent', 'field': 'version', 'baseline': 'v1'}],
            'forbidden_operations': ['UNAPPROVED_ALLOCATION']
        }

    def test_approved_plan_detects_simulated_mutants(self):
        a = audit_warranty(self.warranty())
        self.assertEqual(a['killed'], 2)
        self.assertEqual(a['survived'], 0)

    def test_incomplete_cluster_warranty_exposes_blindspot(self):
        x = self.warranty()
        x['unchanged_fields'] = []
        self.assertGreater(audit_warranty(x)['survived'], 0)

    def test_removed_approval_and_forbidden_action_are_breaking(self):
        old = self.warranty()
        new = copy.deepcopy(old)
        new['steps'][0]['requires_approval'] = False
        new['forbidden_operations'] = []
        self.assertEqual(compare_warranties(old, new)['verdict'], 'BREAKING')

    def test_recovery_rejects_unapproved_consent_mutation(self):
        before = {'consent': {'version': 'v1'}, 'fulfillment': {'recorded': False}}
        after = {'consent': {'version': 'v2'}, 'fulfillment': {'recorded': True}}
        r = verify_recovery(
            before, after, [{'target': 'fulfillment', 'field': 'recorded'}],
            expected=[{'target': 'fulfillment', 'field': 'recorded', 'equals': True}]
        )
        self.assertFalse(r['verified'])
        self.assertTrue(r['unmet_postconditions'] == [])

if __name__ == '__main__':
    unittest.main()

