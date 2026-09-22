"""Application-scoped duplicate cleanup, built on the original transport and locks."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
from pathlib import Path

import requests
from legacy.engine import Client as OriginalClient, Settings, SafetyError, application_locks, connect, bounded_map

REPORT_ID = '54cccc49-3d2e-473c-ac25-c943fd58a0f7'
REPORT_NAME = 'Applications Containing Same Hash'
FIELDS = ('hash', 'fullPath', 'cert', 'processPath', 'installedBy', 'keyFile', 'isHashOnly', 'minSize', 'maxSize', 'notes')
KNOWN = set(FIELDS) | {'applicationFileId','applicationId','applicationName','organizationId','osType','name','createdBy',
    'applicationFileDetails','originalFullPath','originalCert','originalHash','originalProcessPath','originalNotes',
    'originalInstalledBy','originalKeyFile','updateStatus','sha256','sha256Hash','recordType'}


def uid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise SafetyError('Invalid organization or application ID.') from None


def hash_value(value):
    value = str(value or '').strip().upper()
    if not re.fullmatch(r'(?:[A-F0-9]{32}|[A-F0-9]{40}|[A-F0-9]{64})', value):
        raise SafetyError('Invalid report hash; expected 32, 40 or 64 hexadecimal characters.')
    return value


def primary(row):
    return str(row.get('hash') or row.get('originalHash') or '').strip().upper()


def fingerprint(row):
    # All returned fields matter for preservation and stale-plan checks.
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def plain_hash(row):
    try:hash_value(primary(row))
    except SafetyError:return False
    if row.get('isHashOnly') is not True or row.get('keyFile') not in (False, None):
        return False
    if any(row.get(k) for k in ('fullPath','cert','processPath','installedBy')):
        return False
    if any(row.get(k) for k in ('originalFullPath','originalCert','originalProcessPath','originalInstalledBy','originalKeyFile','name')):
        return False
    if any(row.get(k) is not None for k in ('minSize','maxSize')):
        return False
    if row.get('originalHash') and str(row['originalHash']).upper() != primary(row):
        return False
    if any(row.get(k) is not None and row.get(k) != '' for k in set(row) - KNOWN):
        return False
    # Conflicting hash/type indicators are ambiguous, not opportunities to merge.
    if any(row.get(k) and str(row[k]).upper() != primary(row) for k in ('sha256','sha256Hash')):
        return False
    return not row.get('recordType')


def choose(rows):
    if len(rows) < 2:
        return None, [], 'No current duplicates'
    if not all(plain_hash(r) for r in rows):
        return None, [], 'Ambiguous matching fields or key-file/type flag; entire group preserved'
    ordered = sorted(rows, key=lambda r: int(r['applicationFileId']))
    return ordered[0], ordered[1:], 'Lowest numeric applicationFileId retained; notes archived'


def parse_report(content: bytes, name: str, org: str):
    org = uid(org)
    try:
        text = content.decode('utf-8-sig')
        if name.lower().endswith('.json'):
            data = json.loads(text)
            rows = data.get('data') if isinstance(data, dict) else data
        else:
            rows = list(csv.DictReader(io.StringIO(text)))
        if not isinstance(rows, list):
            raise ValueError()
        candidates = {}
        for row in rows:
            fields = {re.sub(r'[^a-z0-9]', '', k.lower()): v for k, v in row.items()}
            row_org = uid(fields['organizationid'])
            if row_org != org:
                raise SafetyError('Report contains another organization. Select/export one organization at a time.')
            app = uid(fields['applicationid'])
            h = hash_value(fields['hash'])
            candidates[(app,h)] = {'ApplicationId':app,'Hash':h,'OrganizationId':org,
                'Name':str(fields.get('name','')), 'Count':fields.get('count')}
        return list(candidates.values()), len(rows)-len(candidates)
    except SafetyError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        raise SafetyError('Report must contain OrganizationId, ApplicationId, and Hash columns.') from None


class Client(OriginalClient):
    def __init__(self, cfg):
        cfg.validate()
        super().__init__(cfg)
        self.requests = Counter()
        self.elapsed = 0.0

    def session(self):
        session = super().session()
        if not getattr(session, '_counted', False):
            def count(response, *args, **kwargs):
                with self.lock:
                    self.requests[f'{response.request.method} {response.request.path_url.split("?")[0]}'] += 1
                    self.elapsed += response.elapsed.total_seconds()
            session.hooks['response'].append(count)
            session._counted = True
        return session

    def metadata(self, app):
        row = self.get('/Application/ApplicationGetById', {'applicationId':uid(app)})
        if not isinstance(row, dict) or uid(row.get('applicationId')) != uid(app):
            raise SafetyError('Application identity mismatch.')
        if uid(row.get('organizationId')) != uid(self.cfg.org) or row.get('osType') not in (1,2):
            raise SafetyError('Application owner/OS mismatch; only Windows and macOS are supported.')
        if row.get('isBuiltIn') is not False:
            raise SafetyError('Built-in or unknown application type cannot be modified.')
        return row

    def post_read(self, path, body):
        # Read-only POSTs can be retried; deletion POSTs retain the legacy no-replay behavior.
        for attempt in range(4):
            try:
                with self.slot():
                    r = self.session().post(self.cfg.base+path,json=body,timeout=(10,self.cfg.timeout),allow_redirects=False)
                    self.throttle(r)
            except requests.RequestException:
                if attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise SafetyError('Report request failed (network/timeout).') from None
            if r.status_code in (429,500,502,503,504) and attempt < 3:
                time.sleep(2**attempt)
                continue
            if r.status_code != 200:
                raise SafetyError(f'Read request HTTP {r.status_code}. Check credentials and organization.')
            try:
                return r.json()
            except ValueError:
                raise SafetyError('Invalid report JSON.') from None

    def report(self, report_id=REPORT_ID):
        now = datetime.now(timezone.utc)
        return self.post_read('/Report/ReportGetDynamicData', {'reportId':uid(report_id),
            'startDate':now.replace(hour=0,minute=0,second=0,microsecond=0).isoformat(),
            'endDate':now.replace(hour=23,minute=59,second=59,microsecond=0).isoformat(),
            'data':'','offsetInMinutes':0,'valid':True,'includeChildOrganizations':False,'options':[]})


def open_db(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    db = connect(directory/'cleanup.sqlite3')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS apps(app TEXT PRIMARY KEY,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS baseline(app TEXT,fid TEXT,body TEXT NOT NULL,PRIMARY KEY(app,fid));
        CREATE TABLE IF NOT EXISTS groups(app TEXT,hash TEXT,survivor TEXT,reason TEXT,PRIMARY KEY(app,hash));
        CREATE TABLE IF NOT EXISTS targets(app TEXT,fid TEXT,hash TEXT,body TEXT,status TEXT,detail TEXT,PRIMARY KEY(app,fid));
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,time REAL,kind TEXT,app TEXT,fid TEXT,detail TEXT);
    ''')
    return db


def put(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(key,json.dumps(value)))
    db.commit()


def get(db, key, default=None):
    row = db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()
    return json.loads(row[0]) if row else default


def event(db, kind, app='', fid='', detail=''):
    db.execute('INSERT INTO events(time,kind,app,fid,detail) VALUES (?,?,?,?,?)',(time.time(),kind,app,fid,detail))
    db.commit()


def scope(cfg):
    return {'org':uid(cfg.org),'instance':cfg.instance,'user_instance':cfg.user_instance}


def map_in_pool(pool, fn, values, workers, cancelled):
    """Legacy bounded submission, with a pool reused across verification waves."""
    iterator=iter(values);pending=set()
    while True:
        while len(pending)<workers and not cancelled():
            try:value=next(iterator)
            except StopIteration:break
            pending.add(pool.submit(fn,value))
        if not pending:return
        done,pending=wait(pending,return_when=FIRST_COMPLETED)
        for future in done:yield future.result()


class Run:
    def __init__(self, cfg, directory, client_factory=Client):
        self.cfg,self.directory,self.client_factory=cfg,Path(directory),client_factory
        self.stop=threading.Event()
        self.progress={'phase':'Idle'}
        self.thread=None

    def update(self, **values):
        self.progress.update(values)

    @property
    def active(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, action, *args):
        if self.active:
            raise SafetyError('This run is already active.')
        self.stop.clear()
        def work():
            try:
                getattr(self,action)(*args)
            except Exception as exc:
                self.update(phase='Stopped',error=str(exc) if isinstance(exc,SafetyError) else type(exc).__name__)
        self.thread=threading.Thread(target=work,daemon=True)
        self.thread.start()

    def prepare(self, candidates, scan_apps=(), os_filter=(1,2)):
        started=time.perf_counter()
        db=open_db(self.directory)
        client=self.client_factory(self.cfg)
        try:
            if get(db,'scope') is not None:
                raise SafetyError('Run already exists; use resume or a new run directory.')
            put(db,'scope',scope(self.cfg));put(db,'created',time.time())
            wanted=defaultdict(set)
            for row in candidates:
                if uid(row['OrganizationId']) != uid(self.cfg.org):
                    raise SafetyError('Candidate organization mismatch.')
                wanted[uid(row['ApplicationId'])].add(hash_value(row['Hash']))
            scan_apps={uid(a) for a in scan_apps}
            appids=sorted(set(wanted)|scan_apps)
            with application_locks(self.cfg,appids):
                for app in appids:
                    if self.stop.is_set():raise SafetyError('Preview stopped; create a new preview.')
                    self.update(phase='Validating',application=app)
                    meta=client.metadata(app)
                    if meta['osType'] not in os_filter:continue
                    db.execute('INSERT INTO apps VALUES (?,?)',(app,json.dumps(meta)))
                    rows=list(client.files(app,cancelled=self.stop.is_set))
                    for row in rows:
                        if row.get('organizationId') and uid(row['organizationId'])!=uid(self.cfg.org):
                            raise SafetyError('Record organization mismatch.')
                        if row.get('osType') not in (None,0,meta['osType']):
                            raise SafetyError('Record OS mismatch.')
                        try:
                            if int(row['applicationFileId'])<=0:raise ValueError()
                        except (ValueError,TypeError):
                            raise SafetyError('Invalid numeric file ID.') from None
                        db.execute('INSERT INTO baseline VALUES (?,?,?)',(app,str(row['applicationFileId']),json.dumps(row)))
                    buckets=defaultdict(list)
                    for row in rows:
                        if primary(row):buckets[primary(row)].append(row)
                    if app in scan_apps:
                        wanted[app].update(h for h,group in buckets.items() if len(group)>1)
                    for h in sorted(wanted[app]):
                        group=buckets.get(h,[])
                        survivor,targets,reason=choose(group)
                        db.execute('INSERT INTO groups VALUES (?,?,?,?)',(app,h,str(survivor['applicationFileId']) if survivor else None,reason))
                        for row in targets:
                            body=dict(row,applicationId=app,osType=meta['osType'],applicationName=meta['name'],organizationId=self.cfg.org)
                            db.execute('INSERT INTO targets VALUES (?,?,?,?,?,?)',(app,str(row['applicationFileId']),h,json.dumps(body),'Planned',''))
                    db.commit()
            put(db,'phase','Ready');put(db,'prepared',time.time());put(db,'preview_seconds',time.perf_counter()-started)
            event(db,'PreviewCreated',detail='Lowest numeric ID retained; ambiguous groups preserved')
            self.update(phase='Ready',**self.counts(db))
        finally:
            self.metrics(db,client,'preview');db.close();client.close()

    def counts(self,db):
        values=Counter({r[0]:r[1] for r in db.execute('SELECT status,COUNT(*) FROM targets GROUP BY status')})
        return {'planned':sum(values.values()),'verified':values['VerifiedAbsent'],
            'remaining':sum(n for s,n in values.items() if s!='VerifiedAbsent'),
            'skipped_groups':db.execute('SELECT COUNT(*) FROM groups WHERE survivor IS NULL').fetchone()[0],
            'statuses':dict(values)}

    def metrics(self,db,client,phase):
        put(db,phase+'_requests',dict(getattr(client,'requests',{})))
        put(db,phase+'_request_seconds',getattr(client,'elapsed',0))
        put(db,phase+'_throttles',getattr(client,'throttles',0))

    def validate_scope(self,db):
        if get(db,'scope') != scope(self.cfg):raise SafetyError('Run belongs to another organization or API instance.')

    def reconcile(self,db,client):
        """Full read-only reconciliation. Never infer absence from a hash-filtered search."""
        self.update(phase='Reconciling')
        for app_row in db.execute('SELECT * FROM apps').fetchall():
            app=app_row['app']; old=json.loads(app_row['body']);meta=client.metadata(app)
            if meta['osType']!=old['osType'] or meta['name']!=old['name']:
                raise SafetyError('Application metadata changed; build a new plan.')
            baseline={r['fid']:json.loads(r['body']) for r in db.execute('SELECT * FROM baseline WHERE app=?',(app,))}
            current={str(r['applicationFileId']):r for r in client.files(app)}
            targets={r['fid']:dict(r) for r in db.execute('SELECT * FROM targets WHERE app=?',(app,))}
            if set(current)-set(baseline):raise SafetyError('New application records detected; existing plan cannot proceed.')
            for fid,row in current.items():
                if fingerprint(row)!=fingerprint(baseline[fid]):raise SafetyError('Record fields changed; existing plan cannot proceed.')
            for fid in set(baseline)-set(current):
                if fid not in targets:raise SafetyError('Retained or unrelated record disappeared; cleanup stopped.')
                if targets[fid]['status']=='Planned':
                    raise SafetyError('Unsubmitted target disappeared; external change detected.')
            for fid,row in targets.items():
                if row['status']=='VerifiedAbsent' and fid in current:
                    raise SafetyError('Previously absent record reappeared; stopped.')
                status='VerifiedAbsent' if fid not in current else ('Planned' if row['status']=='Planned' else 'StillPresent')
                db.execute('UPDATE targets SET status=? WHERE app=? AND fid=?',(status,app,fid))
            db.commit()
        event(db,'Reconciled',detail='Full manifests checked; no writes')

    def execute(self, confirm_count, reconcile_only=False):
        started=time.perf_counter();db=open_db(self.directory);client=self.client_factory(self.cfg)
        try:
            self.validate_scope(db)
            if get(db,'prepared') is None:
                raise SafetyError('Preview did not finish. Create a new preview before execution or reconciliation.')
            appids=[r[0] for r in db.execute('SELECT app FROM apps')]
            with application_locks(self.cfg,appids), ThreadPoolExecutor(max_workers=self.cfg.workers) as pool:
                self.reconcile(db,client)
                if reconcile_only:
                    put(db,'phase','Reconciled');self.update(phase='Reconciled',**self.counts(db));return
                remaining=self.counts(db)['remaining']
                if confirm_count!=remaining:raise SafetyError(f'Confirm the reconciled remaining count: {remaining}.')
                if time.time()-get(db,'prepared',0)>1800:
                    # Full reconciliation above refreshes the plan, without selecting new survivors.
                    event(db,'StalePlanRevalidated')
                put(db,'phase','Executing');event(db,'ExecutionStarted',detail=str(remaining))
                groups=db.execute('SELECT * FROM groups WHERE survivor IS NOT NULL ORDER BY app,hash').fetchall()
                for group in groups:
                    app,h=group['app'],group['hash']
                    while not self.stop.is_set():
                        batch=db.execute("SELECT * FROM targets WHERE app=? AND hash=? AND status IN ('Planned','StillPresent') ORDER BY CAST(fid AS INTEGER) LIMIT ?",(app,h,min(32,self.cfg.batch_size))).fetchall()
                        if not batch:break
                        # Revalidate before each bounded wave; new/deleted/changed matching records stop writes.
                        current=[r for r in client.files(app,h) if primary(r)==h]
                        expected={r['fid']:json.loads(r['body']) for r in db.execute('SELECT * FROM baseline WHERE app=?',(app,)) if primary(json.loads(r['body']))==h}
                        gone={r[0] for r in db.execute("SELECT fid FROM targets WHERE app=? AND hash=? AND status IN ('VerifiedAbsent','Accepted')",(app,h))}
                        expected={fid:r for fid,r in expected.items() if fid not in gone}
                        live={str(r['applicationFileId']):r for r in current}
                        if set(live)!=set(expected) or any(fingerprint(live[fid])!=fingerprint(row) for fid,row in expected.items()):
                            raise SafetyError('Duplicate group changed during execution; stopped before the next wave.')
                        if group['survivor'] not in live or not all(plain_hash(r) for r in current):
                            raise SafetyError('Survivor or matching semantics changed.')
                        for row in batch:
                            db.execute("UPDATE targets SET status='Dispatched' WHERE app=? AND fid=?",(app,row['fid']))
                        db.commit()  # Durable intention precedes every write.
                        self.update(phase='Deleting',application=app,hash=h,**self.counts(db))
                        failed=False
                        def remove(row):
                            ok,detail=client.delete(json.loads(row['body']))
                            if not ok:self.stop.set()
                            return row,ok,detail
                        for row,ok,detail in map_in_pool(pool,remove,batch,self.cfg.workers,self.stop.is_set):
                            db.execute('UPDATE targets SET status=?,detail=? WHERE app=? AND fid=?',('Accepted' if ok else 'Uncertain',detail,app,row['fid']))
                            event(db,'DeleteResponse',app,row['fid'],detail)
                            failed |= not ok
                        db.commit()
                        if failed:
                            self.stop.set()
                        self.update(**self.counts(db))
                        self.metrics(db,client,'execution')
                    if self.stop.is_set():break
                self.reconcile(db,client)
                counts=self.counts(db)
                phase='Complete' if counts['remaining']==0 else 'Stopped; reconcile before resume'
                put(db,'phase',phase);self.update(phase=phase,**counts)
                event(db,'VerificationCompleted',detail=json.dumps(counts))
        except Exception:
            put(db,'phase','Stopped; review required')
            raise
        finally:
            put(db,'execution_seconds',time.perf_counter()-started)
            self.metrics(db,client,'execution');db.close();client.close()

    def audit(self):
        db=open_db(self.directory)
        try:
            return {'metadata':{r['key']:json.loads(r['value']) for r in db.execute('SELECT * FROM meta')},
                'counts':self.counts(db),'groups':[dict(r) for r in db.execute('SELECT * FROM groups')],
                'targets':[dict(r) for r in db.execute('SELECT app,fid,hash,status,detail FROM targets')],
                'events':[dict(r) for r in db.execute('SELECT * FROM events')]}
        finally:db.close()

    def preview(self):
        db=open_db(self.directory)
        try:
            return [dict(r) for r in db.execute('SELECT g.app,g.hash,g.survivor,g.reason,COUNT(t.fid) deletions FROM groups g LEFT JOIN targets t ON g.app=t.app AND g.hash=t.hash GROUP BY g.app,g.hash')]
        finally:db.close()
