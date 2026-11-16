"""Comprehensive test suite for ClusterGuard Autonomous Infrastructure Orchestration & Guardrails."""
import copy
import json
import unittest
from clusterguard.agent import (
    compose, execute, recovery, verify, verify_receipt,
    baseline_comparison, stress_test, mutation_audit, PlanningError
)
from clusterguard.llm_client import LLMClient, LLMUnavailable

INPUT = {
    'mode': 'sample',
    'seed_type': 'objective',
    'anchors': ['Low-Latency AI Cluster', 'High-Throughput Vector Indexer'],
    'constraints': ['soc2_compliant', 'zero_trust_mesh'],
    'instances': 12,
    'people': 12,
    'budget': 40,
    'inventory': {
        'cpu': 40,
        'gpu_h100': 35,
        'ram_gib': 30,
        'nvme_tb': 25,
        'egress_gbps': 20,
        'static_ips': 20
    }
}

class ClusterGuardOrchestrationSuiteTests(unittest.TestCase):
    def plan(self, **changes):
        return compose({**copy.deepcopy(INPUT), **changes})

    def test_plan_finite_and_valid(self):
        p = self.plan()
        self.assertEqual(sum(a['quantity'] for a in p['actions']), 12)
        self.assertLessEqual(p['metrics']['spend'], 40)
        self.assertTrue(all(x >= 0 for x in p['contract']['remaining_inventory'].values()))

    def test_approval_required(self):
        with self.assertRaises(PlanningError):
            execute(self.plan(), approval=False)

    def test_success_observed(self):
        p = self.plan()
        r = execute(p, approval=True)
        self.assertEqual(r['verification']['verdict'], 'PASS')
        self.assertTrue(verify_receipt(r['evidence']))

    def test_false_ack_is_blocked(self):
        r = execute(self.plan(), fault='false_success', approval=True)
        self.assertEqual(r['ack']['status'], 'SUCCESS')
        self.assertEqual(r['verification']['verdict'], 'BLOCK')

    def test_missing_readback_unknown(self):
        r = execute(self.plan(), fault='missing_observation', approval=True)
        self.assertEqual(r['verification']['verdict'], 'UNKNOWN')

    def test_unexpected_side_effect_blocked(self):
        r = execute(self.plan(), fault='unexpected_side_effect', approval=True)
        self.assertEqual(r['verification']['verdict'], 'BLOCK')
        with self.assertRaises(PlanningError):
            recovery(self.plan(), r, approval=True)

    def test_approved_recovery(self):
        p = self.plan()
        r = execute(p, 'false_success', True)
        with self.assertRaises(PlanningError):
            recovery(p, r, False)
        new = recovery(p, r, True)
        self.assertEqual(new['verification']['verdict'], 'PASS')
        self.assertTrue(new['recovered'])
        self.assertEqual(new['observed']['safety_storage']['locked'], True)
        with self.assertRaises(PlanningError):
            recovery(p, new, True)

    def test_contract_tamper_blocks(self):
        p = self.plan()
        p['contract']['remaining_inventory']['cpu'] = 700
        r = execute(p, approval=True)
        self.assertEqual(r['verification']['verdict'], 'BLOCK')

    def test_evidence_tamper(self):
        r = execute(self.plan(), approval=True)
        r['evidence']['verdict'] = 'BLOCK'
        self.assertFalse(verify_receipt(r['evidence']))

    def test_budget_zero_rejected(self):
        with self.assertRaisesRegex(PlanningError, 'Cannot allocate'):
            self.plan(budget=0)

    def test_stock_cannot_be_negative(self):
        i = copy.deepcopy(INPUT['inventory'])
        i['cpu'] = -1
        with self.assertRaises(PlanningError):
            self.plan(inventory=i)

    def test_excess_instances_rejected(self):
        with self.assertRaises(PlanningError):
            self.plan(people=100)

    def test_unknown_constraints_rejected(self):
        with self.assertRaises(PlanningError):
            self.plan(constraints=['unsafe_auto_override'])

    def test_same_rules_different_objectives(self):
        a = self.plan(anchors=['Low-Latency AI Cluster'])
        b = self.plan(anchors=['Zero-Trust Edge Gateway'])
        self.assertNotEqual(
            [(x['id'], x['quantity']) for x in a['actions']],
            [(x['id'], x['quantity']) for x in b['actions']]
        )
        self.assertEqual(a['contract']['unchanged'], b['contract']['unchanged'])

    def test_comparison_is_explicit_not_overclaim(self):
        comp = baseline_comparison(self.plan())
        self.assertTrue(comp['different'])
        self.assertIn('not user preference', comp['note'])

    def test_whatif_reuses_advisor(self):
        p = self.plan()
        result = stress_test(p, {'budget': 4})
        self.assertEqual(result['verdict'], 'BLOCK')
        self.assertTrue(result['same_advisor_evidence'])

    def test_whatif_cannot_modify_objectives(self):
        with self.assertRaises(PlanningError):
            stress_test(self.plan(), {'anchors': ['something']})

    def test_modelled_mutation_engine_reused(self):
        a = mutation_audit(self.plan())
        self.assertGreater(a['mutants'], 0)
        self.assertGreaterEqual(a['killed'], 1)

    def test_live_groq_response_from_fake_transport(self):
        calls = []
        def transport(provider, url, headers, payload):
            calls.append((provider, url))
            return {'choices': [{'message': {'content': json.dumps({'entities': [
                {'id': 'g1', 'name': 'LLM Inference Cluster', 'tags': ['gpu', 'inference', 'realtime', 'low_latency'], 'affinity': 0.92}
            ]})}}]}
        c = LLMClient(groq_key='unit-test-groq', gemini_key='', transport=transport)
        taste = c.optimize('cluster', 'objective', ['Low-Latency AI Cluster'], mode='live')
        self.assertEqual(taste['mode'], 'live')
        self.assertEqual(taste['provider'], 'groq')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], 'Groq')

    def test_live_gemini_fallback_when_groq_fails(self):
        calls = []
        def transport(provider, url, headers, payload):
            calls.append((provider, url))
            if provider == 'Groq':
                raise LLMUnavailable('Rate limit exceeded')
            return {'candidates': [{'content': {'parts': [{'text': json.dumps({'entities': [
                {'id': 'gem1', 'name': 'Zero-Trust Ingress Edge', 'tags': ['gateway', 'zero_trust', 'ingress'], 'affinity': 0.88}
            ]})}]}}]}
        c = LLMClient(groq_key='unit-test-groq', gemini_key='unit-test-gemini', transport=transport)
        taste = c.optimize('cluster', 'objective', ['Zero-Trust Edge Gateway'], mode='live')
        self.assertEqual(taste['mode'], 'live')
        self.assertEqual(taste['provider'], 'gemini')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], 'Groq')
        self.assertEqual(calls[1][0], 'Gemini')

    def test_live_without_key_no_fake_success(self):
        c = LLMClient(groq_key='', gemini_key='')
        with self.assertRaises(LLMUnavailable):
            c.optimize('cluster', 'objective', ['Low-Latency AI Cluster'], mode='live')

if __name__ == '__main__':
    unittest.main()

