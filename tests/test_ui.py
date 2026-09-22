import unittest
import tempfile,json,time
from types import SimpleNamespace
from cleanup import Run,Settings,open_db,put,event
from streamlit.testing.v1 import AppTest

class DashboardTests(unittest.TestCase):
    def test_running_deletion_progress_renders_without_live_requests(self):
        org='11111111-1111-1111-1111-111111111111'
        with tempfile.TemporaryDirectory() as directory:
            cfg=Settings(org,'fake-token');run=Run(cfg,directory);db=open_db(directory)
            put(db,'scope',dict(org=org,instance='d',user_instance='D'));put(db,'prepared',time.time())
            db.execute('INSERT INTO apps VALUES (?,?)',('app',json.dumps({'name':'Simulated progress','osType':1})))
            for i,status in enumerate(['Accepted','Dispatched','Planned']):
                db.execute('INSERT INTO targets VALUES (?,?,?,?,?,?)',('app',str(i),'A'*64,'{}',status,''))
            db.commit();event(db,'ExecutionStarted');event(db,'DeleteResponse','app','0','HTTP 200');db.close()
            run.thread=SimpleNamespace(is_alive=lambda:True);run.update(phase='Deleting')
            app=AppTest.from_file('app.py').run(timeout=20)
            app.text_input(key='org').set_value(org);app.text_input(key='token').set_value('fake-token')
            app.session_state['run']=run;app.run(timeout=20)
            self.assertEqual(len(app.exception),0)
            self.assertGreaterEqual(len(app.get('progress')),3)
            self.assertTrue(any('Last recorded deletion response' in c.value for c in app.caption))

    def test_customer_connection_and_initial_controls(self):
        app=AppTest.from_file('app.py').run(timeout=20)
        self.assertEqual(len(app.exception),0)
        labels={x.label for x in app.text_input}
        self.assertTrue({'Organization ID','API instance','UserInstance','Authorization header value'}<=labels)
        self.assertTrue(next(x for x in app.button if x.label=='Build dry-run preview').disabled)
        app.text_input(key='org').set_value('11111111-1111-1111-1111-111111111111')
        app.text_input(key='token').set_value('fake-token')
        app.run()
        self.assertEqual(len(app.exception),0)
        self.assertFalse(next(x for x in app.button if x.label=='Build dry-run preview').disabled)

    def test_populated_report_metrics(self):
        app=AppTest.from_file('app.py').run(timeout=20)
        org='11111111-1111-1111-1111-111111111111'
        app.text_input(key='org').set_value(org)
        app.text_input(key='token').set_value('fake-token')
        app.session_state['candidate_org']=org
        app.session_state['candidates']=[dict(OrganizationId=org,ApplicationId='22222222-2222-2222-2222-222222222222',Name='Example',Hash='A'*64,Count=701)]
        app.run(timeout=20)
        self.assertEqual(len(app.exception),0)
        values={m.label:m.value for m in app.metric}
        self.assertEqual(values['Applications in selection'],'1')
        self.assertEqual(values['Estimated extra records'],'700')
