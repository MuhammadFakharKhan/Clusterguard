"""ClusterGuard — Autonomous Cloud Resource Orchestrator & Deterministic Guardrail Harness.

Minimal standard-library HTTP service with zero external package dependencies.
Runs isolated in-process simulations with cryptographic contract verification and rate limiting.
"""
from __future__ import annotations
import argparse, json, os, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from .agent import (compose, execute, recovery, mutation_audit, baseline_comparison,
                    stress_test, PlanningError, verify_receipt)
from .llm_client import LLMUnavailable

ROOT = Path(__file__).resolve().parent

# Avoid silently importing repo-local secrets into the process environment.
# Live AI is enabled only when the operator explicitly sets the relevant env vars.
def _load_env_file():
    if os.getenv('CLUSTERGUARD_LOAD_DOTENV') != '1':
        return
    env_path = ROOT / '.env'
    if not env_path.is_file():
        env_path = ROOT.parent / '.env'
    if env_path.is_file():
        try:
            for line in env_path.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k, v = k.strip(), v.strip().strip('"\'')
                if k and k not in os.environ:
                    os.environ[k] = v
        except Exception:
            pass

_load_env_file()

STATIC = {'/': 'index.html', '/index.html': 'index.html', '/style.css': 'style.css', '/app.js': 'app.js'}
CONTENT_TYPE = {'html': 'text/html; charset=utf-8', 'css': 'text/css; charset=utf-8', 'js': 'application/javascript; charset=utf-8'}
SESSIONS = {}; LOCK = threading.RLock(); VISITS = {}; LIVE_COUNT = 0
SESSION_TTL = 3600

def live_ready():
    has_key = bool(os.getenv('GROQ_API_KEY') or os.getenv('GEMINI_API_KEY'))
    enabled = os.getenv('LLM_LIVE_ENABLED', '1') != '0'
    return has_key and enabled

def take_session(sid):
    if not isinstance(sid, str) or len(sid) > 128:
        return None
    with LOCK:
        s = SESSIONS.get(sid)
        if s and time.time() - s['timestamp'] <= SESSION_TTL:
            return s
        if s:
            SESSIONS.pop(sid, None)
        return None

class Handler(BaseHTTPRequestHandler):
    server_version = 'ClusterGuard/1.0'
    
    def send(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf8')
        self.send_response(status)
        for k, v in [('Content-Type', 'application/json; charset=utf-8'),
                     ('Content-Length', str(len(data))),
                     ('Cache-Control', 'no-store'),
                     ('X-Content-Type-Options', 'nosniff'),
                     ('X-Frame-Options', 'DENY'),
                     ('Referrer-Policy', 'no-referrer'),
                     ('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")]:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def get_asset(self, filename):
        p = ROOT / 'static' / filename
        data = p.read_bytes()
        self.send_response(200)
        for k, v in [('Content-Type', CONTENT_TYPE[filename.rsplit('.', 1)[1]]),
                     ('Content-Length', str(len(data))),
                     ('Cache-Control', 'no-cache'),
                     ('X-Content-Type-Options', 'nosniff'),
                     ('X-Frame-Options', 'DENY'),
                     ('Content-Security-Policy',
                      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")]:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path in STATIC:
            return self.get_asset(STATIC[p.path])
        if p.path == '/healthz':
            return self.send(200, {'status': 'ok', 'service': 'ClusterGuard', 'simulation': True})
        if p.path == '/api/status':
            return self.send(200, {
                'product': 'ClusterGuard',
                'live_enabled': live_ready(),
                'mode_note': 'Sample = synthetic heuristics; baseline = zero LLM; live = Groq primary with Gemini fallback.',
                'groq_configured': bool(os.getenv('GROQ_API_KEY')),
                'gemini_configured': bool(os.getenv('GEMINI_API_KEY')),
                'anonymous': True,
                'simulation': True,
                'physical_cloud_mutations': False
            })
        if p.path == '/api/evidence':
            args = parse_qs(p.query)
            s = take_session(args.get('session', [''])[0])
            if not s or not s.get('run'):
                return self.send(404, {'error': 'Execution evidence not found'})
            receipt = s['run']['evidence']
            return self.send(200, {'receipt': receipt, 'self_hash_valid': verify_receipt(receipt)})
        return self.send(404, {'error': 'Endpoint not found'})

    def do_POST(self):
        global LIVE_COUNT
        path = urlparse(self.path).path
        if path not in ('/api/plan', '/api/execute', '/api/recover', '/api/audit', '/api/compare', '/api/whatif'):
            return self.send(404, {'error': 'Unknown operation'})
        host = self.headers.get('Host', '')
        origin = self.headers.get('Origin')
        if origin and origin not in ('http://' + host, 'https://' + host):
            return self.send(403, {'error': 'Cross-origin request denied'})
        if self.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            return self.send(415, {'error': 'Content-Type must be application/json'})
        try:
            n = int(self.headers.get('Content-Length', '0'))
            if n < 2 or n > 12000:
                return self.send(413, {'error': 'Invalid request payload size'})
            body = json.loads(self.rfile.read(n))
            if not isinstance(body, dict):
                raise PlanningError('Expected JSON object')
            now = time.monotonic()
            ip = self.client_address[0]
            with LOCK:
                h = [v for v in VISITS.get(ip, []) if now - v < 60]
                if len(h) >= 24:
                    return self.send(429, {'error': 'Demo rate limit reached. Please wait a minute.'})
                h.append(now)
                VISITS[ip] = h
            if path == '/api/plan':
                if body.get('mode') == 'live':
                    if not live_ready():
                        return self.send(403, {'error': 'Live AI optimization requires configuring GROQ_API_KEY or GEMINI_API_KEY on the server.'})
                    with LOCK:
                        limit = max(0, int(os.getenv('MAX_LIVE_PLANS', '50')))
                        if LIVE_COUNT >= limit:
                            return self.send(429, {'error': 'Live AI optimization quota limit reached'})
                        LIVE_COUNT += 1
                plan = compose(body)
                sid = secrets.token_urlsafe(24)
                with LOCK:
                    for k, s in list(SESSIONS.items()):
                        if time.time() - s['timestamp'] > SESSION_TTL:
                            SESSIONS.pop(k, None)
                    if len(SESSIONS) >= 200:
                        return self.send(503, {'error': 'ClusterGuard orchestration pool at capacity'})
                    SESSIONS[sid] = {'timestamp': time.time(), 'plan': plan, 'run': None}
                return self.send(200, {'session': sid, 'plan': plan})
                
            session_id = body.get('session')
            s = take_session(session_id)
            if not s:
                return self.send(404, {'error': 'Your orchestration session expired; please schedule a new plan'})
            if path == '/api/audit':
                return self.send(200, {'audit': mutation_audit(s['plan'])})
            if path == '/api/compare':
                return self.send(200, {'comparison': baseline_comparison(s['plan'])})
            if path == '/api/whatif':
                return self.send(200, {'whatif': stress_test(s['plan'], body.get('changes'))})
            if path == '/api/execute':
                with LOCK:
                    if s['run'] is not None:
                        return self.send(409, {'error': 'Already executed; start a new plan or run recovery'})
                    s['run'] = execute(s['plan'], fault=body.get('fault', 'none'), approval=body.get('approve'))
                    result = s['run']
                return self.send(200, {'run': result})
            if path == '/api/recover':
                with LOCK:
                    if s['run'] is None:
                        return self.send(409, {'error': 'No prior execution to recover'})
                    s['run'] = recovery(s['plan'], s['run'], approval=body.get('approve'))
                    result = s['run']
                return self.send(200, {'run': result})
        except LLMUnavailable as exc:
            return self.send(503, {'error': str(exc), 'verdict': 'UNKNOWN', 'note': 'The engine never substitutes synthetic data for failed live advisory calls'})
        except (PlanningError, ValueError, KeyError, TypeError) as exc:
            return self.send(400, {'error': str(exc)[:300]})
        except Exception as exc:
            self.log_error('Internal failure: %s', type(exc).__name__)
            return self.send(500, {'error': 'Internal server error. No cluster actions were executed.'})

    def log_message(self, format, *args):
        print('ClusterGuard', format % args)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', default=os.getenv('HOST', '127.0.0.1'))
    p.add_argument('--port', type=int, default=int(os.getenv('PORT', '8765')))
    args = p.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'ClusterGuard listening at http://{args.host}:{args.port} · Live AI: {live_ready()} (Groq: {bool(os.getenv("GROQ_API_KEY"))}, Gemini: {bool(os.getenv("GEMINI_API_KEY"))})')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()
