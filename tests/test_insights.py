import unittest
import json
import tempfile
from insights import report_summary,run_summary,deletion_progress
from cleanup import open_db


class InsightTests(unittest.TestCase):
    def test_deletion_bars_do_not_count_pending_or_uncertain_as_success(self):
        states=['Planned','Dispatched','Accepted','VerifiedAbsent','Uncertain','StillPresent']
        targets=[dict(app='one',fid=str(i),status=s) for i,s in enumerate(states)]
        events=[dict(kind='DeleteResponse',app='one',fid='2',time=i,detail='HTTP 200') for i in range(3)]
        result=deletion_progress({'targets':targets,'events':events})
        self.assertEqual(result['accepted'],2)
        self.assertEqual(result['verified'],1)
        self.assertEqual(result['attention'],2)
        self.assertEqual(result['dispatched'],1)
        self.assertEqual(result['applications'][0]['accepted'],2)
        self.assertEqual(result['recent'][0]['Time'],2)

    def test_empty_deletion_progress(self):
        result=deletion_progress({'targets':[],'events':[]})
        self.assertEqual(result['total'],0)
        self.assertEqual(result['applications'],[])

    def row(self,app='one',h='A',count=4):
        return dict(ApplicationId=app,Hash=h,Count=count,Name='Identical name')

    def test_shared_hashes_and_same_names_keep_separate_application_totals(self):
        summary=report_summary([self.row(),self.row('two'),self.row(h='B',count=11)])
        self.assertEqual(len(summary['applications']),2)
        self.assertEqual(summary['groups'],3)
        self.assertEqual(summary['hashes'],2)
        self.assertEqual(summary['shared_hashes'],1)
        self.assertEqual(summary['extras'],16)

    def test_repeated_rows_do_not_inflate_metrics(self):
        summary=report_summary([self.row()]*3)
        self.assertEqual(summary['extras'],3)
        self.assertEqual(summary['groups'],1)

    def test_unknown_counts_are_not_presented_as_known_zero(self):
        rows=[self.row(h=str(i),count=c) for i,c in enumerate([None,'invalid',0,-1,2.5,'NaN','Infinity'])]
        summary=report_summary(rows+[self.row(h='valid',count='11')])
        self.assertEqual(summary['unknown_counts'],7)
        self.assertEqual(summary['extras'],10)

    def test_http_acceptance_is_not_a_verified_deletion_metric(self):
        with tempfile.TemporaryDirectory() as directory:
            db=open_db(directory)
            db.execute('INSERT INTO apps VALUES (?,?)',('app',json.dumps({'name':'Example','osType':2})))
            for i in range(4):db.execute('INSERT INTO baseline VALUES (?,?,?)',('app',str(i),'{}'))
            for fid,status in [('2','Accepted'),('3','VerifiedAbsent')]:
                db.execute('INSERT INTO targets VALUES (?,?,?,?,?,?)',('app',fid,'hash','{}',status,''))
            db.commit();db.close()
            row=run_summary(directory)[0]
            self.assertEqual(row['Verified deletions'],1)
            self.assertEqual(row['Expected after cleanup'],2)
            self.assertEqual(row['Remaining planned'],1)
