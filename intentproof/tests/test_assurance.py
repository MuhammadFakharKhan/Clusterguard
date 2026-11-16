import copy
import json
import unittest
from pathlib import Path
from intentproof.assurance import audit_warranty, compare_warranties, verify_recovery

ROOT=Path(__file__).resolve().parents[1]
W=json.loads((ROOT/'examples/strong-warranty.json').read_text())

class AssuranceTest(unittest.TestCase):
    def test_strong_warranty_catches_all_modeled_step_faults(self):
        result=audit_warranty(W)
        self.assertEqual(result['survived'],0)
    def test_weak_warranty_reveals_blind_spot(self):
        weak=copy.deepcopy(W)
        weak['postconditions']=[p for p in weak['postconditions'] if p['target']!='living_light']
        self.assertEqual(audit_warranty(weak)['survived'],1)
    def test_drift_approval_critical(self):
        unsafe=copy.deepcopy(W);unsafe['steps'][1]['requires_approval']=False
        self.assertEqual(compare_warranties(W,unsafe)['verdict'],'BREAKING')
    def test_drift_critical_forbidden_removed(self):
        unsafe=copy.deepcopy(W);unsafe['forbidden_operations']=[]
        self.assertEqual(compare_warranties(W,unsafe)['verdict'],'BREAKING')
    def test_safe_alias(self):
        new=copy.deepcopy(W);new['aliases'].append('night time')
        self.assertEqual(compare_warranties(W,new)['verdict'],'SAFE')
    def test_recovery_detects_blast_radius(self):
        before={'light':{'power':'on'},'door':{'locked':True}}
        after={'light':{'power':'off'},'door':{'locked':False}}
        self.assertFalse(verify_recovery(before,after,{('light','power')})['verified'])
    def test_recovery_verifies_postconditions(self):
        before={'light':{'power':'on'},'door':{'locked':True}}
        after={'light':{'power':'off'},'door':{'locked':True}}
        r=verify_recovery(before,after,{('light','power')},[{'target':'door','field':'locked','equals':True}])
        self.assertTrue(r['verified'])
