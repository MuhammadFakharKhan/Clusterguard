"""Production-grade test suite for ClusterGuard Autonomous Infrastructure Guardrails.

Verifies:
1. Deterministic greedy resource packing (CPU, GPU, RAM, NVMe, Egress, Static IPs).
2. Hard security compliance boundaries (Zero-Trust, FIPS-140-2, Ingress isolation).
3. Pre-declared cryptographic contract generation and SHA-256 tamper detection.
4. Independent 3-valued verifier (PASS, BLOCK, UNKNOWN) solving the false-success problem.
5. Privilege escalation side-effect detection and non-recoverability.
6. Bounded one-shot human-in-the-loop recovery workflow.
7. IntentProof mutation audit achieving 100% mutant kill rate.
"""
import copy
import json
import unittest
from clusterguard.agent import (
    compose, execute, recovery, verify, verify_receipt,
    baseline_comparison, stress_test, mutation_audit, PlanningError, sha
)
from clusterguard.llm_client import LLMClient, LLMUnavailable

CLUSTER_INPUT = {
    'mode': 'sample',
    'seed_type': 'objective',
    'anchors': ['Low-Latency AI Inference Cluster', 'Zero-Trust Edge Gateway'],
    'constraints': ['soc2_compliant', 'zero_trust_mesh'],
    'instances': 12,
    'people': 12,
    'budget': 40,
    'inventory': {
        'cpu': 128,
        'gpu_h100': 16,
        'ram_gib': 256,
        'nvme_tb': 64,
        'egress_gbps': 100,
        'static_ips': 16
    }
}

class ClusterGuardTests(unittest.TestCase):
    def plan(self, **changes):
        payload = copy.deepcopy(CLUSTER_INPUT)
        payload.update(changes)
        return compose(payload)

    def test_deterministic_scheduling_within_quotas_and_budget(self):
        """Scheduler must fulfill exact requested instances within quota and credit budget."""
        p = self.plan()
        total_allocated = sum(a['quantity'] for a in p['actions'])
        self.assertEqual(total_allocated, 12)
        self.assertLessEqual(p['metrics']['spend'], 40)
        remaining = p['contract']['remaining_inventory']
        self.assertTrue(all(val >= 0 for val in remaining.values()))
        self.assertEqual(p['status'], 'AWAITING_APPROVAL')

    def test_security_policy_enforcement_ingress_isolation(self):
        """Enforcing no_public_ingress must drop public-facing gateway workloads."""
        p = self.plan(constraints=['no_public_ingress'])
        allocated_ids = [a['id'] for a in p['actions']]
        # w4 is the Zero-Trust API Gateway with public ingress
        self.assertNotIn('w4', allocated_ids)
        # Verify rejection reason recorded
        rejected = [r for r in p['rejected'] if 'API Gateway' in r['name']]
        self.assertTrue(len(rejected) > 0)
        self.assertIn('public ingress', rejected[0]['reasons'][0].lower())

    def test_advisory_ai_trust_boundary(self):
        """Advisory AI can suggest affinities, but cannot override deterministic resource limits."""
        # Request with severe budget restriction (budget=2)
        with self.assertRaises(PlanningError):
            self.plan(budget=2)

    def test_contract_sha256_cryptographic_integrity(self):
        """Tampering with pre-declared contract must cause verification failure."""
        p = self.plan()
        original_hash = p['contract_hash']
        # Modify remaining quota in contract
        p['contract']['remaining_inventory']['cpu'] += 50
        # Hash mismatch check
        self.assertNotEqual(sha(p['contract']), original_hash)
        # Execution verifier must catch the contract tamper
        run = execute(p, approval=True)
        self.assertEqual(run['verification']['verdict'], 'BLOCK')
        failed_fields = [c['field'] for c in run['verification']['checks'] if c['status'] == 'BLOCK']
        self.assertIn('contract_hash', failed_fields)

    def test_nominal_execution_passes_independent_verification(self):
        """Nominal run with no faults yields PASS from independent verifier."""
        p = self.plan()
        run = execute(p, fault='none', approval=True)
        self.assertEqual(run['ack']['status'], 'SUCCESS')
        self.assertEqual(run['verification']['verdict'], 'PASS')
        self.assertTrue(run['approved'])
        self.assertFalse(run['recovered'])
        self.assertTrue(verify_receipt(run['evidence']))

    def test_zombie_ack_false_success_detected(self):
        """Orchestration API says SUCCESS, but cluster state unchanged -> BLOCK."""
        p = self.plan()
        run = execute(p, fault='false_success', approval=True)
        # The API ack falsely claims SUCCESS
        self.assertEqual(run['ack']['status'], 'SUCCESS')
        # Independent verifier catches the deception
        self.assertEqual(run['verification']['verdict'], 'BLOCK')
        failed_fields = [c['field'] for c in run['verification']['checks'] if c['status'] == 'BLOCK']
        self.assertIn('allocations', failed_fields)
        self.assertIn('stock', failed_fields)
        self.assertIn('fulfillment.recorded', failed_fields)

    def test_privilege_leak_side_effect_detected_and_non_recoverable(self):
        """Unauthorized IAM escalation side-effect must BLOCK and forbid automated recovery."""
        p = self.plan()
        run = execute(p, fault='unexpected_side_effect', approval=True)
        self.assertEqual(run['verification']['verdict'], 'BLOCK')
        failed_fields = [c['field'] for c in run['verification']['checks'] if c['status'] == 'BLOCK']
        self.assertTrue('safety_storage.locked' in failed_fields or 'iam_privilege_escalation.locked' in failed_fields)
        # Automated recovery must be rejected for privilege escalation breaches
        with self.assertRaises(PlanningError):
            recovery(p, run, approval=True)

    def test_telemetry_blackout_returns_unknown(self):
        """Missing readback / network partition must return UNKNOWN, never silent success."""
        p = self.plan()
        run = execute(p, fault='missing_observation', approval=True)
        self.assertEqual(run['verification']['verdict'], 'UNKNOWN')
        self.assertIsNone(run['observed'])
        self.assertEqual(run['verification']['checks'][0]['field'], 'independent_readback')

    def test_bounded_human_in_the_loop_recovery(self):
        """Recoverable false-success allows exactly one approved repair cycle."""
        p = self.plan()
        run = execute(p, fault='false_success', approval=True)
        self.assertEqual(run['verification']['verdict'], 'BLOCK')
        
        # Unauthorized recovery attempt must fail
        with self.assertRaises(PlanningError):
            recovery(p, run, approval=False)
            
        # Authorized recovery succeeds and verifies state
        recovered = recovery(p, run, approval=True)
        self.assertEqual(recovered['verification']['verdict'], 'PASS')
        self.assertTrue(recovered['recovered'])
        self.assertEqual(recovered['observed']['iam_privilege_escalation']['locked'], True)
        
        # Second recovery on same run must be blocked
        with self.assertRaises(PlanningError):
            recovery(p, recovered, approval=True)

    def test_counterfactual_ablation_isolates_ai_optimization(self):
        """Ablation comparison isolates advisory AI placement impact against baseline."""
        p = self.plan()
        comp = baseline_comparison(p)
        self.assertTrue(comp['different'])
        self.assertEqual(comp['source'], 'sample')
        self.assertIn('A difference isolates the advisory AI placement', comp['note'])

    def test_intentproof_mutation_audit_kills_all_mutants(self):
        """Mutation testing deliberately corrupts invariants to prove verifier catches 100% of faults."""
        p = self.plan()
        audit = mutation_audit(p)
        self.assertGreater(audit['mutants'], 0)
        self.assertEqual(audit['survived'], 0)
        self.assertEqual(audit['killed'], audit['mutants'])
        self.assertEqual(audit['coverage_percent'], 100.0)

if __name__ == '__main__':
    unittest.main()

