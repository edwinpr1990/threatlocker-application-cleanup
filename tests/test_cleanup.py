import copy,json,tempfile,threading,unittest,uuid
from collections import Counter
from pathlib import Path
from cleanup import Run,Settings,SafetyError,choose,parse_report,open_db,application_locks

ORG='11111111-1111-1111-1111-111111111111'
APP='22222222-2222-2222-2222-222222222222'
APP2='33333333-3333-3333-3333-333333333333'
H='A'*64

def record(fid,h=H,**kw):
    return dict(applicationFileId=fid,applicationId=APP,hash=h,fullPath='',cert='',processPath='',installedBy='',
        keyFile=False,isHashOnly=True,minSize=None,maxSize=None,notes='note '+str(fid),**kw)

class Fake:
    def __init__(self,cfg):self.cfg=cfg;self.requests=Counter();self.elapsed=0;self.throttles=0
    def metadata(self,app):
        return dict(applicationId=app,organizationId=ORG,osType=1,name='Identical name',isBuiltIn=False)
    def files(self,app,search='',cancelled=lambda:False):
        self.requests['GET']+=1
        return iter(copy.deepcopy([r for r in self.rows[app] if not search or search in r['hash']]))
    def delete(self,body):
        self.requests['POST']+=1;self.sent.append(body['applicationFileId'])
        if getattr(self,'reject',False):return False,'HTTP 429'
        self.rows[body['applicationId']]=[r for r in self.rows[body['applicationId']] if r['applicationFileId']!=body['applicationFileId']]
        if getattr(self,'uncertain',False):return False,'Timeout after commit'
        return True,'HTTP 200'
    def close(self):pass

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.cfg=Settings(ORG,'not-a-real-token',workers=2)
        Fake.rows={APP:[record(i) for i in range(1,5)]+[record(8,'B'*64)],APP2:[dict(record(9),applicationId=APP2)]}
        Fake.sent=[];Fake.uncertain=False;Fake.reject=False
    def run_obj(self,name='run'):return Run(self.cfg,Path(self.tmp.name)/name,Fake)
    def candidates(self,app=APP,h=H):return [dict(OrganizationId=ORG,ApplicationId=app,Hash=h,Count=999)]
    def test_keep_lowest_notes_ignored(self):
        survivor,targets,_=choose([record(8),record(2),record(5)])
        self.assertEqual(survivor['applicationFileId'],2);self.assertEqual(len(targets),2)
    def test_ambiguous_group_preserved(self):
        for field,value in [('keyFile',True),('fullPath','c:/a'),('isHashOnly',False),('minSize',0),('newMatchingField','value')]:
            changed=record(2);changed[field]=value
            self.assertEqual(choose([record(1),changed])[1],[])
    def test_invalid_live_hash_preserved(self):
        self.assertEqual(choose([record(1,'invalid'),record(2,'invalid')])[1],[])
    def test_unknown_false_flag_preserved(self):
        self.assertEqual(choose([record(1),record(2,unknownRuleMode=False)])[1],[])
    def test_shared_hash_same_names_different_ids(self):
        r=self.run_obj();before=copy.deepcopy(Fake.rows);r.prepare(self.candidates()+self.candidates(APP2));r.execute(3)
        self.assertEqual(Fake.rows[APP],[before[APP][0],before[APP][-1]])
        self.assertEqual(Fake.rows[APP2],before[APP2]);self.assertEqual(set(Fake.sent),{2,3,4})
    def test_rerun_idempotent(self):
        r=self.run_obj();r.prepare(self.candidates());r.execute(3)
        q=self.run_obj('second');q.prepare(self.candidates());self.assertEqual(q.audit()['counts']['planned'],0)
    def test_uncertain_deleted_reconciled_without_retry(self):
        Fake.uncertain=True;r=self.run_obj();r.prepare(self.candidates());r.execute(3)
        verified=r.audit()['counts']['verified'];self.assertGreaterEqual(verified,1)
        Fake.uncertain=False;q=self.run_obj();q.execute(3-verified)
        self.assertEqual(q.audit()['counts']['verified'],3);self.assertEqual(len(Fake.sent),3)
    def test_rate_limit_present_resume(self):
        Fake.reject=True;r=self.run_obj();r.prepare(self.candidates());r.execute(3)
        self.assertEqual(r.audit()['counts']['verified'],0)
        Fake.reject=False;q=self.run_obj();q.execute(3);self.assertEqual(q.audit()['counts']['verified'],3)
    def test_changed_survivor_blocks(self):
        r=self.run_obj();r.prepare(self.candidates());Fake.rows[APP][0]['notes']='edited'
        with self.assertRaises(SafetyError):r.execute(3)
        self.assertEqual(Fake.sent,[])
    def test_missing_survivor_blocks(self):
        r=self.run_obj();r.prepare(self.candidates());Fake.rows[APP].pop(0)
        with self.assertRaises(SafetyError):r.execute(3)
    def test_new_record_blocks(self):
        r=self.run_obj();r.prepare(self.candidates());Fake.rows[APP].append(record(10))
        with self.assertRaises(SafetyError):r.execute(3)
    def test_wrong_scope_blocks(self):
        r=self.run_obj();r.prepare(self.candidates());r.cfg=Settings(APP,'another-token')
        with self.assertRaises(SafetyError):r.execute(3)
    def test_stale_report_and_duplicate_rows(self):
        rows=self.candidates()*3+self.candidates(h='C'*64)
        parsed,repeated=parse_report(json.dumps({'data':rows}).encode(),'report.json',ORG)
        self.assertEqual(repeated,2)
        r=self.run_obj();r.prepare(parsed);self.assertEqual(r.audit()['counts']['skipped_groups'],1)
    def test_cross_org_report_rejected(self):
        rows=self.candidates();rows[0]['OrganizationId']=APP
        with self.assertRaises(SafetyError):parse_report(json.dumps(rows).encode(),'r.json',ORG)
    def test_csv_export_columns_and_repeated_rows(self):
        body=f'Count,Hash,ApplicationId,Name,OrganizationId\r\n4,{H},{APP},Example,{ORG}\r\n4,{H},{APP},Example,{ORG}\r\n'
        rows,repeated=parse_report(body.encode('utf-8-sig'),'report.csv',ORG)
        self.assertEqual(len(rows),1);self.assertEqual(repeated,1)
        self.assertEqual(rows[0]['ApplicationId'],APP)
    def test_overlapping_application_lock_blocks(self):
        r=self.run_obj();r.prepare(self.candidates())
        with application_locks(self.cfg,[APP]):
            with self.assertRaises(SafetyError):r.execute(3)
        self.assertEqual(Fake.sent,[])
    def test_seven_hundred(self):
        Fake.rows[APP]=[record(i) for i in range(1,702)]+[record(999,'B'*64)]
        r=self.run_obj();r.prepare(self.candidates());r.execute(700)
        self.assertEqual([x['applicationFileId'] for x in Fake.rows[APP]],[1,999])
    def test_persisted_dispatch_recovery(self):
        r=self.run_obj();r.prepare(self.candidates());db=open_db(r.directory)
        db.execute("UPDATE targets SET status='Dispatched' WHERE fid='2'");db.commit();db.close()
        Fake.rows[APP]=[x for x in Fake.rows[APP] if x['applicationFileId']!=2]
        q=self.run_obj();q.execute(2);self.assertEqual(q.audit()['counts']['verified'],3)
    def test_stop_then_resume(self):
        r=self.run_obj();r.prepare(self.candidates());r.stop.set();r.execute(3)
        self.assertEqual(Fake.sent,[]);q=self.run_obj();q.execute(3)
        self.assertEqual(q.audit()['counts']['verified'],3)
    def test_incomplete_preview_cannot_execute(self):
        r=self.run_obj();r.prepare(self.candidates());db=open_db(r.directory)
        db.execute("DELETE FROM meta WHERE key='prepared'");db.commit();db.close()
        with self.assertRaises(SafetyError):r.execute(3)
        self.assertEqual(Fake.sent,[])
    def test_success_response_without_deletion_not_counted(self):
        class NoOp(Fake):
            def delete(self,body):return True,'HTTP 200'
        r=Run(self.cfg,Path(self.tmp.name)/'noop',NoOp);r.prepare(self.candidates());r.execute(3)
        self.assertEqual(r.audit()['counts']['verified'],0)
        self.assertEqual(r.audit()['counts']['remaining'],3)
    def test_expired_credentials_block_before_writes(self):
        r=self.run_obj();r.prepare(self.candidates())
        class Expired(Fake):
            def metadata(self,app):raise SafetyError('HTTP 401')
        r.client_factory=Expired
        with self.assertRaises(SafetyError):r.execute(3)
        self.assertEqual(Fake.sent,[])

if __name__=='__main__':unittest.main()
