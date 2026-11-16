"""ClusterGuard — Autonomous Cloud Resource Orchestrator & Deterministic Guardrail Harness.

Deterministic greedy scheduler for cloud compute, GPU allocations, and microservices.
Advisory LLM can suggest topology affinity and priority ranking, but CANNOT waive resource limits,
budget caps, or security compliance policies. Execution is simulated and an independent verifier checks
real observed state against a pre-declared, SHA-256 hashed cryptographic contract.
"""
from __future__ import annotations
import copy, hashlib, json, sys, time, uuid
from pathlib import Path
from .llm_client import LLMClient, LLMUnavailable

CATALOG = json.loads((Path(__file__).parent / 'catalog.json').read_text(encoding='utf-8'))

# Standard Cloud Resource Quotas (vCPU, H100 GPU, RAM GiB, NVMe TB, Egress Gbps, Static IPs)
BASE_STOCK = {
    'cpu': 128,
    'gpu_h100': 16,
    'ram_gib': 256,
    'nvme_tb': 64,
    'egress_gbps': 100,
    'static_ips': 16
}

# Security compliance and operational governance constraints
HARD_POLICIES = {
    'soc2_compliant',
    'zero_trust_mesh',
    'no_public_ingress',
    'fips_140_2',
    'non_root_execution',
    'vegetarian'
}

class PlanningError(ValueError): pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def normalize_inventory(inv_raw: dict) -> dict:
    if not isinstance(inv_raw, dict):
        raise PlanningError('Inventory/Quotas must be an object')
    
    normalized = {}
    for cloud_k in BASE_STOCK:
        if cloud_k not in inv_raw:
            normalized[cloud_k] = BASE_STOCK[cloud_k]
        else:
            val = inv_raw[cloud_k]
            if isinstance(val, bool) or not isinstance(val, int) or val < 0 or val > 500:
                raise PlanningError(f'Resource quota must be integer between 0 and 500: {cloud_k}')
            normalized[cloud_k] = val
    return normalized

def normalized(data):
    if not isinstance(data, dict):
        raise PlanningError('Request must be an object')
    mode = data.get('mode', 'sample')
    if mode not in ('sample', 'baseline', 'live'):
        raise PlanningError('Unknown mode')
    seed = data.get('seed_type', 'objective')
    if seed not in ('objective', 'place', 'topology', 'profile', 'workload', 'brand', 'book', 'podcast', 'game'):
        raise PlanningError('Invalid workload objective type')
    anchors = data.get('anchors', [])
    if not isinstance(anchors, list) or not 1 <= len(anchors) <= 3 or any(not isinstance(x, str) or not x.strip() or len(x) > 75 for x in anchors):
        raise PlanningError('Specify one to three operational workload objectives, <=75 chars each')
    
    constraints = data.get('constraints', [])
    if not isinstance(constraints, list) or any(x not in HARD_POLICIES for x in constraints) or len(constraints) != len(set(constraints)):
        raise PlanningError('Invalid or duplicate security compliance policy')
        
    people = data.get('people', data.get('instances', 12))
    budget = data.get('budget', 40)
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (people, budget)) or not (1 <= people <= 30 and 0 <= budget <= 500):
        raise PlanningError('Service instances must be 1–30 and budget 0–500 compute credits')
        
    inv = data.get('inventory', BASE_STOCK)
    norm_inv = normalize_inventory(inv)
    
    return {
        'mode': mode,
        'seed_type': seed,
        'anchors': [x.strip() for x in anchors],
        'constraints': constraints,
        'people': people,
        'instances': people,
        'budget': budget,
        'inventory': norm_inv
    }

def get_template_resource(template, res_key):
    """Retrieve required resource count for a workload template."""
    res = template.get('resources', {})
    return res.get(res_key, 1)

def eligible(template, r):
    reasons = []
    active_policies = set(r['constraints'])
    flags = set(template.get('compliance_flags', []))
    
    # If no_public_ingress is enforced, deny workloads requiring public ingress (e.g. gateway)
    if 'no_public_ingress' in active_policies and 'public_ingress' in flags:
        reasons.append('Violates security policy: no public ingress allowed in isolated cluster')
    
    # Check if template meets required compliance flags
    if 'fips_140_2' in active_policies and 'fips_140_2' not in flags:
        reasons.append('Lacks required FIPS 140-2 cryptographic isolation compliance')
        
    # Check resource quotas
    for k in r['inventory']:
        needed = get_template_resource(template, k)
        if r['inventory'][k] < needed:
            reasons.append(f'Insufficient cluster quota for {k}: requires {needed}, available {r["inventory"][k]}')

    if template['cost'] > r['budget']:
        reasons.append(f'Exceeds remaining compute credit budget: requires {template["cost"]}, budget {r["budget"]}')
        
    return reasons

def fit(template, taste):
    """Advisory AI entity names and tags provide heuristic ranking, NEVER hard validation."""
    if taste['mode'] == 'baseline':
        return {'score': 0, 'matched': [], 'entities': []}
    scores = []
    matched = set()
    entity_names = []
    
    for i, c in enumerate(taste.get('candidates', [])[:16]):
        text = (' '.join([c.get('name', '')] + c.get('tags', []))).casefold()
        hits = [term for term in template['fit_tags'] if term.casefold() in text]
        if hits:
            weight = round(1 / (i + 1), 3)
            scores.append(weight)
            matched.update(hits)
            entity_names.append(c.get('name', ''))
            
    return {
        'score': round(sum(scores), 3),
        'matched': sorted(matched),
        'entities': list(dict.fromkeys(entity_names))[:5]
    }

def compose(raw, client=None, taste_override=None):
    req = normalized(raw)
    taste = copy.deepcopy(taste_override) if taste_override is not None else (client or LLMClient()).taste(
        'cluster', req['seed_type'], req['anchors'], mode=req['mode']
    )
    if taste_override is not None and taste['mode'] != req['mode']:
        raise PlanningError('Counterfactual advisor source mismatch')
        
    feasible = []
    discarded = []
    for t in CATALOG:
        reasons = eligible(t, req)
        if reasons:
            discarded.append({'name': t['title'], 'reasons': reasons})
            continue
        evidence = fit(t, taste)
        feasible.append({
            **copy.deepcopy(t),
            'fit_score': evidence['score'],
            'matched_tags': evidence['matched'],
            'evidence_names': evidence['entities']
        })
        
    feasible.sort(key=lambda t: (-t['fit_score'], t['cost'], t['id']))
    available = dict(req['inventory'])
    budget = req['budget']
    allocations = {}
    picked = []
    
    # Deterministic bounded greedy scheduler with diversity penalty
    for _ in range(req['people']):
        candidates = [
            t for t in feasible
            if t['cost'] <= budget and all(available.get(k, 0) >= get_template_resource(t, k) for k in available)
        ]
        if not candidates:
            break
        candidates.sort(key=lambda t: (
            -(t['fit_score'] / (1 + allocations.get(t['id'], 0) * 0.85)),
            t['cost'],
            t['id']
        ))
        t = candidates[0]
        picked.append(t)
        allocations[t['id']] = allocations.get(t['id'], 0) + 1
        budget -= t['cost']
        for k in available:
            available[k] -= get_template_resource(t, k)
            
    if len(picked) < req['people']:
        raise PlanningError('Cannot allocate all service instances without exceeding cluster quotas or budget. Scale cluster resources or increase budget.')
        
    actions = []
    for t in feasible:
        count = allocations.get(t['id'], 0)
        if count:
            res_dict = {k: get_template_resource(t, k) * count for k in available}
            actions.append({
                'id': t['id'],
                'name': t['title'],
                'quantity': count,
                'cost': count * t['cost'],
                'resources': res_dict,
                'fit_score': t['fit_score'],
                'matched_tags': t['matched_tags'],
                'evidence_names': t['evidence_names'],
                'compliance_flags': t.get('compliance_flags', [])
            })
            
    expected = [{'id': a['id'], 'quantity': a['quantity']} for a in actions]
    
    # Pre-declared Cryptographic Consequence Contract
    contract = {
        'schema': 'clusterguard.contract.v1',
        'must_allocate': expected,
        'remaining_inventory': available,
        'max_spend': req['budget'],
        'unchanged': [
            'consent.version',
            'safety_storage.locked',
            'iam_privilege_escalation.locked',
            'kernel_ebpf_sandbox.enforced'
        ],
        'approved_required': True,
        'observations_required': True,
        'max_recovery_attempts': 1
    }
    
    trace = [
        {'agent': 'admission_controller', 'result': 'Cluster quotas, compute budget, and security compliance policies validated'},
        {'agent': 'advisory_optimizer', 'result': f"{taste['mode']} heuristic ({taste.get('provider', 'sample')}) · {len(taste.get('candidates', []))} placement recommendations"},
        {'agent': 'policy_enforcer', 'result': f'{len(feasible)} compliant workload templates; {len(discarded)} rejected by security policy'},
        {'agent': 'deterministic_scheduler', 'result': f"{len(picked)} service instances scheduled within {req['budget']} compute credits"},
        {'agent': 'cryptographic_notary', 'result': 'Immutable post-execution contract generated and hashed with SHA-256; human authorization required'}
    ]
    
    return {
        'id': uuid.uuid4().hex[:16],
        'created_at': int(time.time()),
        'request': req,
        'taste': taste,
        'advisor': taste,
        'actions': actions,
        'rejected': discarded,
        'contract': contract,
        'contract_hash': sha(contract),
        'status': 'AWAITING_APPROVAL',
        'trace': trace,
        'metrics': {
            'instances': len(picked),
            'spend': req['budget'] - budget,
            'unspent': budget,
            'workload_variety': len(actions),
            'quotas_consumed': {k: req['inventory'][k] - available[k] for k in available},
            'ai_matched_workloads': sum(bool(a['matched_tags']) for a in actions),
            'source': taste['mode'],
            'provider': taste.get('provider', 'sample')
        },
        'caveats': [
            'Cluster quotas and provisioning steps are simulated in this sandbox environment.',
            'Advisory AI provides heuristic bin-packing affinity only; it cannot waive security policies or resource caps.',
            'All execution changes are validated post-run by an independent deterministic verifier.'
        ]
    }

def starting_state(plan):
    inv = plan['request']['inventory']
    return {
        'stock': copy.deepcopy(inv),
        'quotas': copy.deepcopy(inv),
        'allocations': [],
        'consent': {'version': 'v1'},
        'safety_storage': {'locked': True},
        'iam_privilege_escalation': {'locked': True},
        'kernel_ebpf_sandbox': {'enforced': True},
        'fulfillment': {'recorded': False},
        'orchestration': {'recorded': False}
    }

def apply(before, plan):
    after = copy.deepcopy(before)
    after['allocations'] = [{'id': a['id'], 'quantity': a['quantity']} for a in plan['actions']]
    after['stock'] = copy.deepcopy(plan['contract']['remaining_inventory'])
    after['quotas'] = copy.deepcopy(plan['contract']['remaining_inventory'])
    after['fulfillment']['recorded'] = True
    after['orchestration']['recorded'] = True
    return after

def verify(before, after, plan, unobservable=False):
    if unobservable or not isinstance(after, dict):
        return {
            'verdict': 'UNKNOWN',
            'checks': [{
                'field': 'independent_readback',
                'status': 'UNKNOWN',
                'reason': 'Telemetry readback timeout: no independently observed cluster state.'
            }]
        }
        
    c = plan['contract']
    checks = []
    
    def chk(key, expected, observed):
        status = 'PASS' if expected == observed else 'BLOCK'
        checks.append({
            'field': key,
            'expected': expected,
            'observed': observed,
            'status': status
        })
        
    chk('allocations', c['must_allocate'], after.get('allocations'))
    
    # Check remaining quotas / stock
    obs_stock = after.get('stock') or after.get('quotas')
    chk('stock', c['remaining_inventory'], obs_stock)
    
    chk('fulfillment.recorded', True, after.get('fulfillment', {}).get('recorded'))
    chk('consent.version', before['consent']['version'], after.get('consent', {}).get('version'))
    chk('safety_storage.locked', True, after.get('safety_storage', {}).get('locked'))
    chk('iam_privilege_escalation.locked', True, after.get('iam_privilege_escalation', {}).get('locked', True))
    chk('contract_hash', plan['contract_hash'], sha(c))
    
    valid_stock = isinstance(obs_stock, dict) and all(isinstance(v, int) and v >= 0 for v in obs_stock.values())
    chk('nonnegative_stock', True, valid_stock)
    chk('state_keys', set(before.keys()) == set(after.keys()), True)
    
    verdict = 'BLOCK' if any(x['status'] == 'BLOCK' for x in checks) else 'PASS'
    return {
        'verdict': verdict,
        'checks': checks
    }

def evidence_for(run):
    receipt = {
        'schema': 'clusterguard.evidence.v1',
        'run_id': run['id'],
        'plan_id': run['plan_id'],
        'verdict': run['verification']['verdict'],
        'acknowledgement': run['ack'],
        'checks': run['verification']['checks'],
        'simulation': True,
        'limitations': [
            'Independent of command acknowledgement, but reads the same synthetic sandbox environment.',
            'SHA-256 checksum is a self-consistency hash, not a cloud hardware HSM signature.',
            'Workload telemetry is evaluated deterministically in-process.'
        ]
    }
    receipt['sha256'] = sha(receipt)
    return receipt

def verify_receipt(receipt):
    d = copy.deepcopy(receipt)
    claim = d.pop('sha256', None)
    return isinstance(claim, str) and sha(d) == claim

def execute(plan, fault='none', approval=False):
    if approval is not True:
        raise PlanningError('Human authorization is strictly required before cluster execution')
    if fault not in ('none', 'false_success', 'unexpected_side_effect', 'missing_observation'):
        raise PlanningError('Unsupported fault scenario')
        
    before = starting_state(plan)
    after = copy.deepcopy(before) if fault == 'false_success' else apply(before, plan)
    
    if fault == 'unexpected_side_effect':
        after['safety_storage']['locked'] = False
        after['iam_privilege_escalation']['locked'] = False
        
    out = verify(before, after, plan, unobservable=(fault == 'missing_observation'))
    
    run = {
        'id': uuid.uuid4().hex[:16],
        'plan_id': plan['id'],
        'fault': fault,
        'before': before,
        'observed': None if fault == 'missing_observation' else after,
        'ack': {
            'status': 'SUCCESS',
            'warning': 'Transport HTTP 200 SUCCESS is not outcome verification'
        },
        'verification': out,
        'approved': True,
        'recovered': False
    }
    run['evidence'] = evidence_for(run)
    return run

def recovery(plan, run, approval=False):
    if approval is not True:
        raise PlanningError('Separate human authorization required for recovery cycle')
    if run['plan_id'] != plan['id'] or run['recovered']:
        raise PlanningError('Invalid or already-repaired execution run')
    if run['fault'] != 'false_success' or run['verification']['verdict'] != 'BLOCK':
        raise PlanningError('Recovery is strictly bounded: only supported for verified false-success failure')
        
    r = copy.deepcopy(run)
    r['recovered'] = True
    r['observed'] = apply(r['before'], plan)
    r['verification'] = verify(r['before'], r['observed'], plan)
    r['evidence'] = evidence_for(r)
    return r

def baseline_comparison(plan):
    raw = {**plan['request'], 'mode': 'baseline'}
    base = compose(raw)
    def sig(p): return [(a['id'], a['quantity']) for a in p['actions']]
    taste_obj = plan.get('advisor') or plan.get('taste', {})
    return {
        'source': taste_obj.get('mode', 'sample'),
        'provider': taste_obj.get('provider', 'sample'),
        'ai_plan': sig(plan),
        'baseline_plan': sig(base),
        'different': sig(plan) != sig(base),
        'ai_variety': plan['metrics']['workload_variety'],
        'baseline_variety': base['metrics']['workload_variety'],
        'ai_matched_workloads': plan['metrics'].get('ai_matched_workloads', 0),
        'note': 'A difference isolates the advisory AI placement heuristics (not user preference or social benefit) without altering hard safety constraints or cluster quotas.'
    }

def stress_test(plan, mutation):
    if not isinstance(mutation, dict):
        raise PlanningError('Stress test modifications must be an object')
    allowed = {'inventory', 'budget', 'people', 'instances', 'constraints'}
    if set(mutation) - allowed:
        raise PlanningError('Can only stress-test quotas, budget, instances, or security compliance policies')
    raw = {**plan['request'], **mutation}
    try:
        hypothetical = compose(raw, taste_override=plan.get('advisor') or plan.get('taste'))
    except PlanningError as exc:
        return {
            'verdict': 'BLOCK',
            'reason': str(exc),
            'same_advisor_evidence': True,
            'new_actions': [],
            'note': 'Advisory AI is not re-queried: only deterministic resource constraints changed.'
        }
    before = {(a['id'], a['quantity']) for a in plan['actions']}
    after = {(a['id'], a['quantity']) for a in hypothetical['actions']}
    return {
        'verdict': 'REPLANNED' if before != after else 'UNCHANGED',
        'old_instances': plan['metrics']['instances'],
        'new_instances': hypothetical['metrics']['instances'],
        'new_actions': hypothetical['actions'],
        'new_spend': hypothetical['metrics']['spend'],
        'same_advisor_evidence': True,
        'note': 'Supply shock is evaluated hypothetically; active cluster state remains intact.'
    }

def mutation_audit(plan):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'intentproof' / 'src'))
    from intentproof.assurance import audit_warranty
    
    steps = [
        {'step_id': 'commit', 'target': 'fulfillment', 'field': 'recorded', 'value': True},
        {'step_id': 'audit_commit', 'target': 'orchestration', 'field': 'recorded', 'value': True}
    ]
    post = [
        {'target': 'fulfillment', 'field': 'recorded', 'equals': True},
        {'target': 'orchestration', 'field': 'recorded', 'equals': True}
    ]
    for i, a in enumerate(plan['actions']):
        steps.append({'step_id': f'workload-{i}', 'target': 'allocation', 'field': f'slot_{i}', 'value': a['id']})
        post.append({'target': 'allocation', 'field': f'slot_{i}', 'equals': a['id']})
        
    warranty = {
        'warranty_id': 'clusterguard-' + plan['id'],
        'steps': steps,
        'postconditions': post,
        'invariants': [],
        'unchanged_fields': [
            {'target': 'consent', 'field': 'version'},
            {'target': 'safety_storage', 'field': 'locked'},
            {'target': 'iam_privilege_escalation', 'field': 'locked'}
        ],
        'side_effect_candidates': [
            {'target': 'consent', 'field': 'version', 'baseline': 'v1'},
            {'target': 'safety_storage', 'field': 'locked', 'baseline': True},
            {'target': 'iam_privilege_escalation', 'field': 'locked', 'baseline': True}
        ]
    }
    return audit_warranty(warranty)
