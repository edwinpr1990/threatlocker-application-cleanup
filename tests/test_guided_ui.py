import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
from cleanup import SafetyError,Settings,Run,open_db,put
from guided_ui import find_applications,history_rows
from test_consolidation import Fake,source,ConsolidationRun,ORG,APP

class SearchClient:
    def __init__(self,pages):self.pages=iter(pages);self.cfg=SimpleNamespace(org=ORG);self.bodies=[]
    def post_read(self,path,body):self.bodies.append(body);return next(self.pages)

class GuidedTests(unittest.TestCase):
    def row(self,aid=APP,**kw):return dict(applicationId=aid,organizationId=ORG,osType=1,isBuiltIn=False,name='Same name',**kw)
    def test_search_pagination_and_identical_names(self):
        second='33333333-3333-3333-3333-333333333333'
        c=SearchClient([[self.row()],[self.row(second)],[]]);rows=find_applications(c,' test ',1)
        self.assertEqual(len(rows),2);self.assertEqual([r['pageNumber'] for r in c.bodies],[1,2,3])
        self.assertTrue(all(not b['includeChildOrganizations'] and not b['includeMaster'] for b in c.bodies))
    def test_repeated_and_cross_org_fail_closed(self):
        with self.assertRaises(SafetyError):find_applications(SearchClient([[self.row()],[self.row()]]),'',1)
        bad=self.row();bad['organizationId']=APP
        with self.assertRaises(SafetyError):find_applications(SearchClient([[bad]]),'',1)
    def test_wrong_os_or_builtin_fail_closed(self):
        for change in [{'osType':2},{'isBuiltIn':True}]:
            row=self.row();row.update(change)
            with self.assertRaises(SafetyError):find_applications(SearchClient([[row]]),'',1)
    def test_combined_history_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=Settings(ORG,'fake-token');db=open_db(Path(tmp)/'hash')
            put(db,'scope',dict(org=ORG,instance='d',user_instance='D'));put(db,'created',1);put(db,'phase','Complete');db.close()
            Fake.rows=[source(i) for i in range(1,4)]
            run=ConsolidationRun(cfg,Path(tmp)/'conditions',Fake);run.prepare(APP,'balanced')
            rows=history_rows(cfg,Path(tmp));self.assertEqual({r['Workflow'] for r in rows},{'Duplicate hashes','Conditional rules'})
            self.assertEqual(history_rows(Settings(APP,'fake-token'),Path(tmp)),[])
    def test_picker_selection_and_scope_isolation(self):
        app=AppTest.from_file('portal_app.py').run(timeout=25)
        app.text_input(key='org').set_value(ORG);app.text_input(key='token').set_value('fake-token')
        app.session_state['conditions_picker_results']={'scope':(ORG,'d','D'),'rows':[self.row()],'loaded':1,'query':'Same','os':'Windows'}
        app.run(timeout=25)
        app.selectbox(key='conditions_picker_selected').set_value(APP).run()
        next(b for b in app.button if b.label=='Use this application').click().run()
        self.assertEqual(app.text_input(key='consolidation_app').value,APP)
        app.text_input(key='org').set_value('33333333-3333-3333-3333-333333333333').run()
        self.assertEqual(len(app.exception),0)
        self.assertFalse(any(x.label=='Choose an application' for x in app.selectbox))
    def test_changed_selection_does_not_retarget_saved_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=Settings(ORG,'fake-token');Fake.rows=[source(i) for i in range(1,11)]
            run=ConsolidationRun(cfg,tmp,Fake);run.prepare(APP,'balanced')
            app=AppTest.from_file('portal_app.py').run(timeout=25)
            app.text_input(key='org').set_value(ORG);app.text_input(key='token').set_value('fake-token')
            app.session_state['consolidation_run']=run;app.session_state['consolidation_app']='33333333-3333-3333-3333-333333333333'
            app.run(timeout=25)
            app.checkbox(key='conditions_reviewed').set_value(True)
            app.text_input(key='conditions_confirm').set_value('APPLY 10').run(timeout=25)
            self.assertEqual(len(app.exception),0)
            self.assertTrue(any('selection has changed' in a.value for a in app.info))
            self.assertEqual(run.audit()['app'],APP)
            self.assertEqual({m.label:m.value for m in app.metric}['Resulting records'],'1')
            self.assertTrue(next(b for b in app.button if b.label=='Apply reviewed conditional rules').disabled)

if __name__=='__main__':unittest.main()
