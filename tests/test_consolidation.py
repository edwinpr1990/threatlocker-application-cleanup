import copy,json,tempfile,unittest
from pathlib import Path
from collections import Counter
from cleanup import Settings,SafetyError
from consolidation import ConsolidationRun,optimize
from large_apps import parse

ORG='11111111-1111-1111-1111-111111111111'
APP='22222222-2222-2222-2222-222222222222'

def source(i):
    return {'applicationFileId':i,'applicationId':APP,'hash':f'{i:064X}','fullPath':'','processPath':'','cert':'','installedBy':'',
        'isHashOnly':True,'keyFile':False,'minSize':None,'maxSize':None,
        'notes':fr'Path: C:\Program Files\Codex Fixture\App\1.2.{i}\agent.exe'+'\n'+r'Process: C:\Program Files\Codex Fixture\launcher.exe'}

class Fake:
    rows=[];sent=[];lost=False;reject=False
    def __init__(self,cfg):self.cfg=cfg;self.requests=Counter()
    def metadata(self,app):return dict(applicationId=app,organizationId=ORG,osType=1,name='Test',isBuiltIn=False)
    def files(self,app):return iter(copy.deepcopy(self.rows))
    def close(self):pass
    def insert_rule(self,body):
        self.requests['insert']+=1
        if self.reject:return False,'HTTP 429'
        self.rows.append(dict(body,applicationFileId=100+len(self.rows)))
        return (False,'Timeout') if self.lost else (True,'HTTP 200')
    def delete(self,body):
        self.requests['delete']+=1;self.sent.append(body['applicationFileId'])
        self.rows[:]=[r for r in self.rows if r['applicationFileId']!=body['applicationFileId']]
        return (False,'Timeout') if self.lost else (True,'HTTP 200')

class ConsolidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.cfg=Settings(ORG,'not-real');Fake.rows=[source(i) for i in range(1,11)]+[dict(source(99),notes='No observation')]
        Fake.sent=[];Fake.lost=False;Fake.reject=False
    def runobj(self,name='run'):return ConsolidationRun(self.cfg,Path(self.tmp.name)/name,Fake)
    def test_coverage_preserves_fallback_and_custom_rules(self):
        custom=dict(source(77),isHashOnly=False,fullPath=r'c:\custom\*')
        result=optimize(Fake.rows+[custom],'balanced')
        self.assertEqual(len(result['targets']),10);self.assertEqual(len(result['rules']),1)
        self.assertEqual(result['fallback'],[Fake.rows[-1],custom])
    def test_live_style_apply_preserves_fields_and_rerun_zero(self):
        original=copy.deepcopy(Fake.rows[-1]);r=self.runobj();r.prepare(APP,'balanced');r.execute(10)
        self.assertIn(original,Fake.rows);self.assertEqual(len(Fake.rows),2)
        self.assertEqual(set(Fake.sent),set(range(1,11)))
        self.assertEqual(r.audit()['phase'],'Complete')
        rerun=self.runobj('second');self.assertEqual(len(rerun.prepare(APP,'balanced')['plan']['targets']),0)
    def test_uncertain_committed_writes_not_replayed(self):
        Fake.lost=True;r=self.runobj();r.prepare(APP,'balanced');r.execute(10)
        self.assertEqual(len(Fake.sent),10);self.assertEqual(len(Fake.rows),2)
    def test_changed_record_stops_all_writes(self):
        r=self.runobj();r.prepare(APP,'balanced');Fake.rows[0]['notes']='changed'
        with self.assertRaises(SafetyError):r.execute(10)
        self.assertEqual(Fake.sent,[]);self.assertEqual(len(Fake.rows),11)
    def test_failed_insert_blocks_deletion_and_blind_resume(self):
        Fake.reject=True;r=self.runobj();r.prepare(APP,'balanced')
        with self.assertRaises(SafetyError):r.execute(10)
        Fake.reject=False
        with self.assertRaises(SafetyError):self.runobj().execute(10)
        self.assertEqual(Fake.sent,[])
    def test_new_record_blocks(self):
        r=self.runobj();r.prepare(APP,'balanced');Fake.rows.append(source(120))
        with self.assertRaises(SafetyError):r.execute(10)
    def test_interrupt_and_resume_keep_verified_replacements(self):
        r=self.runobj();r.prepare(APP,'balanced')
        original=Fake.delete
        def interrupted(client,body):
            value=original(client,body);r.stop.set();return value
        Fake.delete=interrupted
        try:r.execute(10)
        finally:Fake.delete=original
        self.assertEqual(r.audit()['phase'],'Stopped');self.assertEqual(len(Fake.sent),1)
        restored=self.runobj();restored.execute(10)
        self.assertEqual(len(Fake.sent),10);self.assertEqual(len(Fake.rows),2)
    def test_multiple_notes_and_keyfile_preserved(self):
        rows=[dict(source(1),notes=source(1)['notes']+'\nPath: c:\\other.exe'),dict(source(2),keyFile=True)]
        self.assertEqual(optimize(rows)['targets'],[])
    def test_mac_apply_not_yet_enabled(self):self.assertEqual(optimize(Fake.rows,'balanced',2)['targets'],[])
    def test_scope_blocks(self):
        r=self.runobj();r.prepare(APP,'balanced');r.cfg=Settings(APP,'not-real')
        with self.assertRaises(SafetyError):r.execute(10)
    def test_transient_windows_rename_retries_only_journal(self):
        from unittest.mock import patch
        import os
        original=os.replace;calls=[]
        def transient(a,b):
            calls.append(1)
            if len(calls)==1:raise PermissionError('simulated Windows reader')
            return original(a,b)
        r=self.runobj()
        with patch('consolidation.os.replace',side_effect=transient):r.prepare(APP,'balanced')
        self.assertEqual(len(calls),2);self.assertEqual(Fake.sent,[])
    def test_large_report_repeated_and_invalid_counts(self):
        row=dict(ApplicationId=APP,OrganizationId=ORG,Name='Test',**{'Count of Hashes':1001})
        self.assertEqual(len(parse(json.dumps([row,row]).encode(),'a.json',ORG)),1)
        row['Count of Hashes']=-1
        with self.assertRaises(SafetyError):parse(json.dumps([row]).encode(),'a.json',ORG)
    def test_large_report_rejects_cross_org(self):
        with self.assertRaises(SafetyError):parse(json.dumps([dict(ApplicationId=APP,OrganizationId=APP,**{'Count of Hashes':1001})]).encode(),'a.json',ORG)

if __name__=='__main__':unittest.main()
