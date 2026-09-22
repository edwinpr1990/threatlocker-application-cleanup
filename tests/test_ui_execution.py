"""Controlled UI executions: actual cleanup engines, in-memory API doubles."""
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
from cleanup import Run as RealRun
from consolidation import ConsolidationRun as RealConsolidation
from test_cleanup import Fake as HashFake,record,ORG,APP
from test_consolidation import Fake as ConditionsFake,source

class UIExecutionTests(unittest.TestCase):
    def connected(self):
        app=AppTest.from_file('portal_app.py').run(timeout=25)
        app.text_input(key='org').set_value(ORG);app.text_input(key='token').set_value('fake-token')
        return app
    def test_hash_preview_execute_and_idempotent_repreview_through_ui(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Run(RealRun):
                def __init__(self,cfg,directory,*args):super().__init__(cfg,Path(tmp)/Path(directory).name,HashFake)
            HashFake.rows={APP:[record(i) for i in range(1,5)]+[record(9,'B'*64)]}
            HashFake.sent=[];HashFake.reject=False;HashFake.uncertain=False
            with patch('cleanup.Run',Run):
                app=self.connected()
                next(x for x in app.text_area if x.label=='Additional application IDs to scan').set_value(APP)
                next(b for b in app.button if b.label=='Build dry-run preview').click().run(timeout=25)
                app.session_state['run'].thread.join(10);app.run(timeout=25)
                app.text_input(key='confirm').set_value('DELETE 3').run()
                next(b for b in app.button if b.label=='Delete reviewed duplicate records').click().run(timeout=25)
                app.session_state['run'].thread.join(10);app.run(timeout=25)
                self.assertEqual(len(app.exception),0)
                self.assertEqual(app.session_state['run'].audit()['counts']['verified'],3)
                self.assertEqual([r['applicationFileId'] for r in HashFake.rows[APP]],[1,9])
                next(b for b in app.button if b.label=='Build dry-run preview').click().run(timeout=25)
                app.session_state['run'].thread.join(10)
                self.assertEqual(app.session_state['run'].audit()['counts']['planned'],0)
    def test_conditions_preview_execute_and_download_controls_through_ui(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Run(RealConsolidation):
                def __init__(self,cfg,directory,*args):super().__init__(cfg,Path(tmp)/Path(directory).name,ConditionsFake)
            ConditionsFake.rows=[source(i) for i in range(1,11)]+[dict(source(99),notes='Preserve')]
            ConditionsFake.sent=[];ConditionsFake.lost=False;ConditionsFake.reject=False
            # The UI module may already be cached by another test.
            with patch('consolidation.ConsolidationRun',Run),patch('consolidation_ui.ConsolidationRun',Run):
                app=self.connected();app.text_input(key='consolidation_app').set_value(APP)
                next(s for s in app.selectbox if s.label=='Rule suggestion profile').set_value('Balanced')
                next(b for b in app.button if b.label=='Build conditional-rule preview').click().run(timeout=25)
                self.assertEqual(len(app.exception),0)
                app.checkbox(key='conditions_reviewed').set_value(True)
                app.text_input(key='conditions_confirm').set_value('APPLY 10').run()
                next(b for b in app.button if b.label=='Apply reviewed conditional rules').click().run(timeout=25)
                app.session_state['consolidation_run'].thread.join(10);app.run(timeout=25)
                self.assertEqual(len(app.exception),0)
                self.assertEqual(app.session_state['consolidation_run'].audit()['phase'],'Complete',str(app.session_state['consolidation_run'].progress))
                self.assertEqual(len(ConditionsFake.rows),2)
                self.assertTrue(any('Saved verification passed' in s.value for s in app.success))
                self.assertGreaterEqual(len(app.get('download_button')),3)

if __name__=='__main__':unittest.main()
