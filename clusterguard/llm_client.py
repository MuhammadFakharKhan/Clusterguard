"""ClusterGuard Advisory Workload Optimizer with Groq (primary) and Gemini (fallback).

Zero external dependencies: uses Python standard library urllib.request.
Provides heuristic workload placement affinities, node topology tags, and priority ranking.
Maintains a strict trust boundary: advisory AI suggestions are validated by the deterministic
resource packer and can NEVER override resource bounds, spending limits, or security invariants.
"""
from __future__ import annotations
import json
import os
import re
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

GROQ_ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions'
DEFAULT_GROQ_MODEL = 'openai/gpt-oss-120b'
DEFAULT_GEMINI_MODEL = 'gemini-3.8-flash'

class LLMUnavailable(RuntimeError):
    pass

# Enterprise cloud topology and workload affinity profiles for zero-credential sample runs.
SAMPLE_PROFILES = {
    'deep_learning': [
        ('LLM Inference Acceleration Core', ['gpu', 'inference', 'low_latency', 'ai_workload', 'realtime', 'tensorrt', 'vllm']),
        ('Distributed GPU Training Worker', ['training', 'gpu', 'high_compute', 'batch', 'fine_tuning', 'fsdp', 'lora']),
        ('Realtime Observability eBPF Daemon', ['telemetry', 'observability', 'ebpf', 'security'])
    ],
    'zero_trust_edge': [
        ('Zero-Trust Edge Ingress Router', ['gateway', 'networking', 'ingress', 'zero_trust', 'low_latency', 'edge']),
        ('eBPF Kernel Anomaly Sensor', ['telemetry', 'observability', 'ebpf', 'streaming', 'security', 'kernel']),
        ('Cryptographic Key & Token Service', ['zero_trust', 'fips_140_2', 'gateway'])
    ],
    'data_platform': [
        ('Distributed Vector DB Indexer', ['vector_db', 'rag', 'high_memory', 'nvme_storage', 'search', 'hnsw', 'database']),
        ('RAG Context Retriever & Embedder', ['embedding', 'batch', 'cpu_bound', 'rag', 'search', 'semantic']),
        ('High-Throughput Stream Processor', ['telemetry', 'streaming', 'database', 'observability'])
    ]
}

def sample_candidates(anchors: list[str]):
    text = ' '.join(anchors).lower()
    if any(v in text for v in ('olive', 'mediterranean', 'edge', 'security', 'zero_trust', 'gateway', 'ingress', 'fips', 'ebpf', 'network', 'cava')):
        profile = 'zero_trust_edge'
    elif any(v in text for v in ('vector', 'data', 'search', 'rag', 'database', 'milvus', 'qdrant', 'embed', 'storage', 'retriev')) :
        profile = 'data_platform'
    else:
        profile = 'deep_learning'
    return profile, [
        {
            'id': f'urn:clusterguard:topology:{profile}:{i}',
            'name': '[Sample Heuristic] ' + n,
            'tags': tags,
            'affinity': round(0.96 - (i * 0.1), 2),
            'sample': True
        }
        for i, (n, tags) in enumerate(SAMPLE_PROFILES[profile])
    ]

def _clean_json_text(raw_text: str) -> str:
    """Strip markdown code blocks if the LLM wrapped JSON in ```json ... ```."""
    text = raw_text.strip()
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s*```$', '', text)
    return text.strip()

def _normalize_entities(raw_entities: list) -> list[dict]:
    entities = []
    if not isinstance(raw_entities, list):
        return []
    for i, item in enumerate(raw_entities):
        if not isinstance(item, dict):
            continue
        name = item.get('name') or item.get('title') or item.get('service') or item.get('workload')
        if not name:
            continue
        raw_tags = item.get('tags') or item.get('affinities') or item.get('keywords') or []
        tags = []
        if isinstance(raw_tags, list):
            for t in raw_tags:
                if isinstance(t, str) and t.strip():
                    tags.append(t.strip().lower()[:50])
                elif isinstance(t, dict):
                    val = t.get('name') or t.get('tag')
                    if val and isinstance(val, str):
                        tags.append(val.strip().lower()[:50])
        elif isinstance(raw_tags, str):
            tags = [x.strip().lower()[:50] for x in raw_tags.split(',') if x.strip()]
        
        affinity = item.get('affinity')
        try:
            affinity = round(float(affinity), 3) if affinity is not None else round(0.95 - (i * 0.08), 2)
        except (TypeError, ValueError):
            affinity = 0.85
            
        eid = str(item.get('id') or f'topology-heuristic-{i+1}')
        entities.append({
            'id': eid,
            'name': str(name)[:100],
            'tags': tags[:20],
            'affinity': affinity,
            'sample': False
        })
    return entities

class LLMClient:
    def __init__(self, groq_key: str | None = None, gemini_key: str | None = None, transport = None):
        self.groq_key = groq_key if groq_key is not None else os.getenv('GROQ_API_KEY', '')
        self.gemini_key = gemini_key if gemini_key is not None else os.getenv('GEMINI_API_KEY', '')
        self.groq_model = os.getenv('GROQ_MODEL', DEFAULT_GROQ_MODEL)
        self.gemini_model = os.getenv('GEMINI_MODEL', DEFAULT_GEMINI_MODEL)
        self.transport = transport or self._default_http

    def _default_http(self, provider: str, url: str, headers: dict, payload: dict) -> dict:
        data = json.dumps(payload).encode('utf-8')
        req = Request(url, data=data, headers=headers, method='POST')
        try:
            with urlopen(req, timeout=12) as res:
                if res.status != 200:
                    raise LLMUnavailable(f'{provider} returned HTTP {res.status}')
                raw = res.read(1024 * 1024).decode('utf-8')
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            status = getattr(exc, 'code', None)
            reason = getattr(exc, 'reason', str(exc))
            raise LLMUnavailable(f'{provider} request failed: {status or reason}') from None

    def _call_groq(self, anchors: list[str]) -> list[dict]:
        if not self.groq_key:
            raise LLMUnavailable('GROQ_API_KEY is not configured')
        prompt_system = (
            "You are an enterprise AI Infrastructure Topology Optimizer for ClusterGuard. "
            "Given SRE deployment objectives and operational affinity anchors, return a JSON object with key 'entities'. "
            "'entities' must be a list of 3 to 6 microservice placement heuristics or workload affinity profiles. "
            "Each entity must contain: 'id' (string), 'name' (string), 'tags' (list of lowercase strings matching "
            "infrastructure requirements: gpu, inference, vector_db, rag, high_memory, nvme_storage, gateway, networking, ingress, zero_trust, low_latency, telemetry, observability, ebpf, training, batch), "
            "and 'affinity' (float 0.7-1.0). Return JSON ONLY."
        )
        payload = {
            "model": self.groq_model,
            "messages": [
                {"role": "system", "content": prompt_system},
                {"role": "user", "content": f"Operational workload objectives: {', '.join(anchors)}"}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        headers = {
            "Authorization": f"Bearer {self.groq_key}",
            "Content-Type": "application/json",
            "User-Agent": "ClusterGuard/1.0"
        }
        res = self.transport('Groq', GROQ_ENDPOINT, headers, payload)
        content = res.get('choices', [{}])[0].get('message', {}).get('content', '')
        parsed = json.loads(_clean_json_text(content))
        entities = _normalize_entities(parsed.get('entities', []))
        if not entities:
            raise LLMUnavailable('Groq returned empty workload entities')
        return entities

    def _call_gemini(self, anchors: list[str]) -> list[dict]:
        if not self.gemini_key:
            raise LLMUnavailable('GEMINI_API_KEY is not configured')
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={self.gemini_key}"
        prompt = (
            "You are an enterprise AI Infrastructure Topology Optimizer for ClusterGuard.\n"
            f"Given these operational workload placement objectives: {', '.join(anchors)}\n"
            "Return a JSON object with key 'entities'. "
            "'entities' must be a list of 3 to 6 microservice placement heuristics or workload affinity profiles. "
            "Each entity must have: 'id' (string), 'name' (string), 'tags' (list of lowercase strings matching: "
            "gpu, inference, vector_db, rag, high_memory, nvme_storage, gateway, networking, ingress, zero_trust, low_latency, telemetry, observability, ebpf, training, batch), "
            "and 'affinity' (float between 0.7 and 1.0).\n"
            "Return JSON ONLY."
        )
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2
            }
        }
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ClusterGuard/1.0"
        }
        res = self.transport('Gemini', url, headers, payload)
        candidates = res.get('candidates', [])
        if not candidates:
            raise LLMUnavailable('Gemini returned no candidates')
        text = candidates[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        parsed = json.loads(_clean_json_text(text))
        entities = _normalize_entities(parsed.get('entities', []))
        if not entities:
            raise LLMUnavailable('Gemini returned empty workload entities')
        return entities

    def taste(self, track: str, seed_type: str, anchors: list[str], mode: str = 'sample') -> dict:
        """Alias for optimize() maintaining contract compatibility."""
        return self.optimize(track=track, seed_type=seed_type, anchors=anchors, mode=mode)

    def optimize(self, track: str = 'cluster', seed_type: str = 'objective', anchors: list[str] | None = None, mode: str = 'sample') -> dict:
        anchors = [str(x).strip()[:75] for x in (anchors or []) if str(x).strip()][:3]
        if not anchors:
            anchors = ['Low-Latency AI Cluster Inference']
            
        trace = []
        if mode == 'baseline':
            return {
                'mode': 'baseline',
                'provider': 'none',
                'anchors': anchors,
                'resolved': [],
                'candidates': [],
                'trace': [{'tool': 'Deterministic Baseline (Zero LLM Advisor)', 'status': 'SKIPPED'}]
            }

        if mode == 'sample':
            profile, candidates = sample_candidates(anchors)
            return {
                'mode': 'sample',
                'provider': 'fixture',
                'anchors': anchors,
                'resolved': [{'id': f'urn:clusterguard:objective:{i}', 'name': f'[Sample Objective] {v}', 'sample': True} for i, v in enumerate(anchors)],
                'candidates': candidates,
                'trace': [{
                    'tool': 'Transparent Workload Topology Heuristic Fixture',
                    'status': 'SAMPLE',
                    'profile': profile,
                    'note': 'Deterministic placement heuristic for zero-credential evaluation.'
                }]
            }

        if mode != 'live':
            raise ValueError(f'Unknown source mode: {mode}')

        # Live mode: Try Groq first, then fall back to Gemini
        candidates = []
        errors = []
        provider_used = None

        if self.groq_key:
            start_t = time.monotonic()
            try:
                candidates = self._call_groq(anchors)
                ms = round((time.monotonic() - start_t) * 1000)
                trace.append({
                    'tool': f'Groq ({self.groq_model})',
                    'status': 'SUCCESS',
                    'latency_ms': ms,
                    'provider': 'groq'
                })
                provider_used = 'groq'
            except Exception as e:
                errors.append(f"Groq failed: {str(e)}")
                trace.append({
                    'tool': f'Groq ({self.groq_model})',
                    'status': 'FAILED',
                    'error': str(e)
                })

        if not candidates and self.gemini_key:
            start_t = time.monotonic()
            try:
                candidates = self._call_gemini(anchors)
                ms = round((time.monotonic() - start_t) * 1000)
                trace.append({
                    'tool': f'Gemini ({self.gemini_model})',
                    'status': 'SUCCESS',
                    'latency_ms': ms,
                    'provider': 'gemini'
                })
                provider_used = 'gemini'
            except Exception as e:
                errors.append(f"Gemini failed: {str(e)}")
                trace.append({
                    'tool': f'Gemini ({self.gemini_model})',
                    'status': 'FAILED',
                    'error': str(e)
                })

        if not candidates:
            msg = ' | '.join(errors) if errors else 'No live LLM credentials configured'
            raise LLMUnavailable(msg)

        return {
            'mode': 'live',
            'provider': provider_used,
            'anchors': anchors,
            'resolved': [{'id': f'urn:clusterguard:live:{i}', 'name': v, 'sample': False} for i, v in enumerate(anchors)],
            'candidates': candidates,
            'trace': trace
        }
