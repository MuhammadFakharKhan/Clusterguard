import json,threading,unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from clusterguard.server import Handler
class HttpTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
    cls.s=ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.port=cls.s.server_address[1]
    cls.t=threading.Thread(target=cls.s.serve_forever,daemon=True);cls.t.start()
 @classmethod
 def tearDownClass(cls):cls.s.shutdown();cls.s.server_close();cls.t.join(3)
 def ask(self,path,payload=None,method=None):
    data=json.dumps(payload).encode() if payload is not None else None
    req=Request(f'http://127.0.0.1:{self.port}{path}',data=data,method=method,headers={'Content-Type':'application/json'} if data else {})
    with urlopen(req,timeout=5) as r:return r.status,json.loads(r.read())
 def test_home_served(self):
    with urlopen(f'http://127.0.0.1:{self.port}/',timeout=5) as r:
        self.assertIn(b'clusterguard',r.read().lower())
 def test_complete_http_loop(self):
    p={'anchors':['Olive Table'],'mode':'sample','seed_type':'place','people':12,'budget':40,'constraints':['vegetarian']}
    _,d=self.ask('/api/plan',p);sid=d['session']
    _,d=self.ask('/api/execute',{'session':sid,'approve':True,'fault':'false_success'})
    self.assertEqual(d['run']['verification']['verdict'],'BLOCK')
    _,d=self.ask('/api/compare',{'session':sid});self.assertIn('different',d['comparison'])
    _,d=self.ask('/api/whatif',{'session':sid,'changes':{'budget':2}});self.assertEqual(d['whatif']['verdict'],'BLOCK')
    _,d=self.ask('/api/recover',{'session':sid,'approve':True});self.assertEqual(d['run']['verification']['verdict'],'PASS')
    _,e=self.ask('/api/evidence?session='+sid)
    self.assertTrue(e['self_hash_valid'])
 def test_disabled_live(self):
    try:self.ask('/api/plan',{'mode':'live','anchors':['Olive Table']})
    except HTTPError as e:self.assertEqual(e.code,403)
    else:self.fail('Live mode unexpectedly enabled in test runtime')
 def test_wrong_origin_rejected(self):
    req=Request(f'http://127.0.0.1:{self.port}/api/plan',data=b'{}',headers={'Content-Type':'application/json','Origin':'https://evil.example'})
    with self.assertRaises(HTTPError) as err:urlopen(req,timeout=5)
    self.assertEqual(err.exception.code,403)
if __name__=='__main__':unittest.main()
