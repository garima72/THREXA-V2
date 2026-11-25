import io, json, os, tempfile, unittest
import app as application

class ThrexaApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_db = None
        import advanced
        cls.advanced = advanced
        cls.tmp = tempfile.NamedTemporaryFile(delete=False)
        cls.tmp.close()
        advanced.DB = advanced.Path(cls.tmp.name)
        advanced.init_db()
        application.app.config['TESTING'] = True
        cls.client = application.app.test_client()
    @classmethod
    def tearDownClass(cls):
        try: os.unlink(cls.tmp.name)
        except OSError: pass
    def test_health(self):
        self.assertEqual(self.client.get('/api/health').status_code,200)
    def test_risk_returns_assets(self):
        d=self.client.get('/api/risk').get_json(); self.assertGreater(len(d['items']),0); self.assertIn('factors',d['items'][0])
    def test_simulation_is_non_destructive(self):
        r=self.client.post('/api/simulate',json={'node_id':'D01'}); self.assertEqual(r.status_code,200); self.assertIn('No host',r.get_json()['disclaimer'])
    def test_ingest_and_incident(self):
        r=self.client.post('/api/logs/ingest',json={'events':[{'severity':'high','title':'test','entities':['D01']}]}); self.assertEqual(r.status_code,200); self.assertEqual(r.get_json()['accepted'],1)
        r=self.client.post('/api/incidents',json={'title':'Test incident','severity':'high','entities':['D01']}); self.assertEqual(r.status_code,201); iid=r.get_json()['incident']['id']
        r=self.client.patch('/api/incidents/'+iid,json={'status':'Investigating','note':'Reviewed'}); self.assertEqual(r.status_code,200); self.assertEqual(r.get_json()['incident']['status'],'Investigating')
    def test_bad_entity_rejected(self):
        r=self.client.post('/api/incidents',json={'title':'Bad','entities':['NOT-A-NODE']}); self.assertEqual(r.status_code,400)

if __name__=='__main__': unittest.main()
