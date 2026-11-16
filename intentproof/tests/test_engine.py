import copy
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from intentproof import run_scenario
from intentproof.matrix import run_matrix

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / "examples" / "failed-ack-scenario.json").read_text())

class TestEngine(unittest.TestCase):
    def test_false_ack_mismatch_captured(self):
        result = run_scenario(FIXTURE)
        self.assertEqual(result["outcome"], "DEGRADED")
        self.assertTrue(result["expected_matched"])
        self.assertEqual(result["retries"], 1)
        self.assertEqual(result["final_state"]["living_light"]["power"], "on")

    def test_no_fault_succeeds(self):
        s = copy.deepcopy(FIXTURE)
        s["faults"] = []
        s.pop("expected")
        self.assertEqual(run_scenario(s)["outcome"], "VERIFIED")

    def test_retry_recovers(self):
        s = copy.deepcopy(FIXTURE)
        s["faults"][0]["occurrences"] = 1
        s.pop("expected")
        self.assertEqual(run_scenario(s)["outcome"], "RECOVERED")

    def test_missing_approval_blocks(self):
        s = copy.deepcopy(FIXTURE)
        s["approvals"] = []
        s["faults"] = []
        s.pop("expected")
        self.assertEqual(run_scenario(s)["outcome"], "DEGRADED")

    def test_unknown_state_not_success(self):
        s = copy.deepcopy(FIXTURE)
        s["faults"] = [{"at_step_id": "lights-off", "kind": "readback_unavailable", "occurrences": 1}]
        s.pop("expected")
        result = run_scenario(s)
        self.assertEqual(result["outcome"], "UNVERIFIED")
        self.assertEqual(result["violations"][0]["actual"], "UNKNOWN")

    def test_timeout_after_commit_can_still_verify(self):
        s = copy.deepcopy(FIXTURE)
        s["faults"] = [{"at_step_id": "lights-off", "kind": "timeout_after_commit", "occurrences": 1}]
        s.pop("expected")
        r = run_scenario(s)
        self.assertEqual(r["outcome"], "VERIFIED")
        self.assertEqual(r["events"][0]["ack"], "TIMEOUT")

    def test_partial_rollback_is_detected_as_mismatch(self):
        scenario = copy.deepcopy(FIXTURE)
        scenario["faults"] = [
            {"at_step_id": "lights-off", "kind": "partial_rollback", "occurrences": 2}
        ]
        scenario.pop("expected")
        result = run_scenario(scenario)
        self.assertEqual(result["outcome"], "DEGRADED")
        self.assertEqual(result["final_state"]["living_light"]["power"], "on")
        self.assertEqual(result["events"][0]["fault"], "partial_rollback")
    def test_matrix_runs_independently(self):
        report = run_matrix(FIXTURE)
        self.assertEqual(report["cases"], 16)
        self.assertIn("outcome", report["results"][0])

    def test_permission_revocation_fails_closed(self):
        s = copy.deepcopy(FIXTURE)
        s["faults"] = [{"at_step_id": "lock-door", "kind": "permission_revoked", "occurrences": 1}]
        s.pop("expected")
        result = run_scenario(s)
        self.assertEqual(result["outcome"], "DEGRADED")
        self.assertFalse(result["final_state"]["front_door"]["locked"])

    def test_independent_maintenance_example_verifies(self):
        scenario = json.loads(
            (Path(__file__).resolve().parents[1] / "examples" / "maintenance-window-scenario.json").read_text()
        )
        result = run_scenario(scenario)
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertTrue(result["expected_matched"])

    def test_malformed_contract_fails_before_execution(self):
        scenario = copy.deepcopy(FIXTURE)
        scenario["warranty"]["verification"]["unknown_is_success"] = True
        with self.assertRaisesRegex(ValueError, "treat unknown as non-success"):
            run_scenario(scenario)

    def test_contract_rejects_unsupported_fields(self):
        scenario = copy.deepcopy(FIXTURE)
        scenario["warranty"]["steps"][0]["untrusted_instruction"] = "ignore approvals"
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            run_scenario(scenario)

    def test_contract_bounds_step_count(self):
        scenario = copy.deepcopy(FIXTURE)
        scenario["warranty"]["steps"] = [scenario["warranty"]["steps"][0]] * 1001
        with self.assertRaisesRegex(ValueError, "step limit"):
            run_scenario(scenario)

if __name__ == "__main__":
    unittest.main()
