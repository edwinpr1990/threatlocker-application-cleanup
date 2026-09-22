"""Reviewed, in-place hash-to-condition consolidation; never clones or edits policies."""
import json
import os
import re
import threading
import time
from pathlib import Path
import pandas as pd
import requests
from cleanup import Client, SafetyError, application_locks, fingerprint, plain_hash, uid, KNOWN
from legacy import optimizer_logic as logic

FIELDS={'Path':'fullPath','Process Path':'processPath','Certificate':'cert','Created By':'installedBy'}
_JOURNAL_LOCKS={}
_JOURNAL_GUARD=threading.Lock()


def journal_lock(path):
    key=str(Path(path).resolve()).lower()
    with _JOURNAL_GUARD:return _JOURNAL_LOCKS.setdefault(key,threading.RLock())


def read_journal(path):
    with journal_lock(path):return json.loads(Path(path).read_text(encoding='utf-8'))


def text(v):
    return str(v).strip() if v is not None and not pd.isna(v) else ''


def matches(pattern, value, windows=True):
    if not pattern:return True
    if not value:return False
    # Only literal characters and '*' are interpreted. No regex, brackets or '?'.
    return re.fullmatch(re.escape(pattern).replace(r'\*','.*'),value,re.I if windows else 0) is not None


def observations(record):
    note=record.get('notes') or ''
    if len(re.findall(r'(?i)(?<!process )\bpath\s*:',note))>1:return None
    p=logic.parse_notes_value(note)
    return {'Path':text(p.path),'Process Path':text(p.process_path),
            'Certificate':text(p.certificate_primary),'Created By':text(p.created_by)}


def optimize(records, profile='conservative', os_type=1):
    """Legacy candidates are suggestions; independent matching decides coverage.

    Unknown fields/custom rules remain intact. Positive coverage is an observation
    check, not proof of security equivalence or ThreatLocker agent matching.
    """
    eligible=[r for r in records if plain_hash(r) and observations(r)]
    source=[{'Hash':r['hash'],'Notes':r.get('notes','')} for r in eligible]
    if not source:
        return {'rules':[],'targets':[],'fallback':records,'reviews':[], 'source_count':len(records),'profile':profile}
    settings=logic.settings_from_aggressiveness(profile)
    settings.wildcard_head_levels=max(4,settings.wildcard_head_levels)
    settings.min_dynamic_head_depth=max(4,settings.min_dynamic_head_depth)
    outputs=logic.build_outputs(pd.DataFrame(source),settings)
    candidates=json.loads(outputs['final_rules'].to_json(orient='records'))
    rules=[];reviews=[];covered=set()
    for candidate in candidates:
        rule={k:text(candidate.get(k)) for k in FIELDS}
        conditions=sum(bool(v) for v in rule.values())
        reasons=[]
        if conditions<2 or not rule['Path']:reasons.append('Requires path plus another condition')
        if any('?' in v or v.lower().startswith('regex:') for v in rule.values()):reasons.append('Unsupported matching syntax')
        if any('*' in rule[k] for k in ('Process Path','Certificate','Created By')):reasons.append('Identity anchors must be exact')
        path=rule['Path'].lower()
        if not path.startswith(('c:\\program files\\','c:\\program files (x86)\\')):
            reasons.append('Live consolidation limited to Windows Program Files paths')
        if len(path.split('\\*')[0].split('\\'))<4:reasons.append('Path is too broad')
        if logic.is_high_risk_process_path(rule['Process Path']) and conditions<3:reasons.append('High-risk process needs three conditions')
        ids=[]
        for record in eligible:
            observation=observations(record)
            if all(matches(rule[k],observation[k],os_type==1) for k in FIELDS):ids.append(str(record['applicationFileId']))
        new=set(ids)-covered
        if len(new)<2:reasons.append('Fewer than two additional source records covered')
        if os_type!=1:reasons.append('macOS candidate application is not yet live validated')
        reviews.append(dict(rule,**{'Covered observations':len(ids),'Status':'Preserved / review' if reasons else 'Review required',
                                  'Reason':'; '.join(reasons) or 'Expands beyond exact hashes; review conditions before applying'}))
        if not reasons:
            rules.append({'fields':rule,'source_ids':sorted(new,key=int)})
            covered.update(new)
    return {'rules':rules,'targets':[r for r in eligible if str(r['applicationFileId']) in covered],
            'fallback':[r for r in records if str(r['applicationFileId']) not in covered],
            'reviews':reviews,'source_count':len(records),'profile':profile}


class ConsolidationClient(Client):
    def insert_rule(self, body):
        try:
            with self.slot():
                r=self.session().post(self.cfg.base+'/ApplicationFile/ApplicationFileInsert',json=body,
                    timeout=(10,self.cfg.timeout),allow_redirects=False)
                self.throttle(r)
            return 200<=r.status_code<300, f'HTTP {r.status_code}'
        except requests.RequestException:return False,'Network/timeout; outcome unknown'


class ConsolidationRun:
    def __init__(self,cfg,directory,client_factory=ConsolidationClient):
        self.cfg=cfg;self.directory=Path(directory);self.factory=client_factory
        self.path=self.directory/'consolidation.json';self.active=False;self.stop=threading.Event()
        self.progress={'phase':'Ready'}

    def save(self,data):
        self.directory.mkdir(parents=True,exist_ok=True)
        temporary=self.path.with_suffix('.tmp')
        with journal_lock(self.path):
            with temporary.open('w',encoding='utf-8') as f:
                json.dump(data,f,indent=2);f.flush();os.fsync(f.fileno())
            # Windows briefly denies replacement while another process reads the
            # destination. Retry only this local atomic rename, never an API write.
            for attempt in range(6):
                try:os.replace(temporary,self.path);break
                except PermissionError:
                    if attempt==5:raise
                    time.sleep(.02*2**attempt)

    def audit(self):return read_journal(self.path)

    def scope(self):return {'org':self.cfg.org,'instance':self.cfg.instance,'user_instance':self.cfg.user_instance}

    def prepare(self,app,profile='conservative'):
        if self.path.exists():raise SafetyError('Use a new run directory for a new preview.')
        c=self.factory(self.cfg)
        try:
            meta=c.metadata(uid(app));rows=list(c.files(app))
            self.validate_rows(rows,app,meta['osType'])
            plan=optimize(rows,profile,meta['osType'])
            data={'scope':self.scope(),'app':app,'metadata':meta,'baseline':rows,'plan':plan,'created':time.time(),
                  'phase':'Preview','insertions':[],'deletions':{},'events':[]}
            self.save(data);return data
        finally:c.close()

    def validate_rows(self,rows,app,os_type):
        ids=set()
        for r in rows:
            rid=str(r['applicationFileId'])
            if not rid.isdigit() or rid in ids:raise SafetyError('Invalid or repeated application-file IDs.')
            if r.get('applicationId') not in (None,app):raise SafetyError('Cross-application record received.')
            if r.get('organizationId') not in (None,self.cfg.org):raise SafetyError('Cross-organization record received.')
            if r.get('osType') not in (None,0,os_type):raise SafetyError('Application-file OS mismatch.')
            ids.add(rid)

    def reconcile(self,c,data):
        if c.metadata(data['app'])!=data['metadata']:raise SafetyError('Application metadata changed; stop and review.')
        rows=list(c.files(data['app']));self.validate_rows(rows,data['app'],data['metadata']['osType'])
        current={str(r['applicationFileId']):r for r in rows}
        baseline={str(r['applicationFileId']):r for r in data['baseline']}
        extra=set(current)-set(baseline)
        for insertion in data['insertions']:
            expected=insertion['body']
            found=[r for rid,r in current.items() if rid in extra and r.get('notes')==expected['notes']
                   and all(text(r.get(field))==text(expected[field]) for field in FIELDS.values())
                   and not r.get('hash') and r.get('isHashOnly') is False and not r.get('keyFile')]
            if len(found)!=1:
                raise SafetyError('Inserted rule missing or ambiguous. No hash deletion/re-insertion; review this run.')
            r=found[0];rid=str(r['applicationFileId'])
            if any(r.get(k) is not None for k in ('minSize','maxSize')) or any(r.get(k) for k in ('originalHash','originalKeyFile','name','recordType')):
                raise SafetyError('Inserted rule has unexpected matching semantics.')
            if any(r.get(k) is not None and r.get(k)!='' for k in set(r)-KNOWN):
                raise SafetyError('Inserted rule contains an unrecognized populated field.')
            for field in FIELDS.values():
                original='original'+field[0].upper()+field[1:]
                if r.get(original) is not None and text(r[original])!=text(expected[field]):
                    raise SafetyError('Inserted rule original fields disagree with the reviewed conditions.')
            if insertion.get('record') and fingerprint(insertion['record'])!=fingerprint(r):raise SafetyError('Inserted rule changed.')
            insertion.update(record=r,status='Verified');extra.remove(rid)
        if extra:raise SafetyError('Application gained unrelated records; stop and rebuild the preview.')
        for rid,original in baseline.items():
            if rid in current:
                if data['deletions'].get(rid)=='Verified':raise SafetyError('A previously absent record reappeared; stop and review.')
                if fingerprint(original)!=fingerprint(current[rid]):raise SafetyError('Source or retained record changed.')
            elif rid not in data['deletions']:
                raise SafetyError('An unsubmitted record disappeared; stop and review.')
            else:data['deletions'][rid]='Verified'
        self.save(data)
        return current

    def execute(self,confirmed_count):
        data=self.audit()
        if data['scope']!=self.scope():raise SafetyError('Connection does not match this run.')
        if confirmed_count!=len(data['plan']['targets']):raise SafetyError('Reviewed target count does not match.')
        c=self.factory(self.cfg);started=time.perf_counter()
        try:
            with application_locks(self.cfg,[data['app']]):
                self.reconcile(c,data)
                data['phase']='Applying reviewed conditions';self.save(data)
                for i,rule in enumerate(data['plan']['rules']):
                    if self.stop.is_set():break
                    if i<len(data['insertions']):continue
                    # Revalidate the complete manifest before each write.
                    self.reconcile(c,data)
                    body={'applicationFileId':0,'applicationId':data['app'],'applicationName':data['metadata']['name'],
                          'organizationId':self.cfg.org,'osType':data['metadata']['osType'],'hash':'','keyFile':False,
                          'isHashOnly':False,'updateStatus':0,'notes':f'Consolidation {self.directory.name} rule {i+1}'}
                    body.update({field:rule['fields'][label] for label,field in FIELDS.items()})
                    data['insertions'].append({'body':body,'status':'Dispatched'});self.save(data)
                    ok,detail=c.insert_rule(body)
                    data['events'].append({'time':time.time(),'action':'Insert','detail':detail});self.save(data)
                    self.reconcile(c,data) # Uncertain responses are reconciled, never blindly replayed.
                if self.stop.is_set():data['phase']='Stopped';self.save(data);return
                if len(data['insertions'])!=len(data['plan']['rules']):raise SafetyError('Not all replacement rules are verified.')
                data['phase']='Removing covered hashes'
                for r in data['plan']['targets']:
                    if self.stop.is_set():break
                    rid=str(r['applicationFileId'])
                    current=self.reconcile(c,data)
                    if rid not in current:continue
                    data['deletions'][rid]='Dispatched';self.save(data)
                    body=dict(r,applicationId=data['app'],applicationName=data['metadata']['name'],
                              organizationId=self.cfg.org,osType=data['metadata']['osType'])
                    ok,detail=c.delete(body)
                    data['events'].append({'time':time.time(),'action':'Delete','id':rid,'detail':detail});self.save(data)
                    current=self.reconcile(c,data)
                    verified=sum(v=='Verified' for v in data['deletions'].values())
                    self.progress={'phase':'Removing covered hashes','verified':verified,'planned':confirmed_count,'last_record':rid}
                    if rid in current:raise SafetyError('Deletion not verified; paused. Resume reconciles before retrying.')
                self.reconcile(c,data)
                data['phase']='Stopped' if self.stop.is_set() else 'Complete'
                data['verified_at']=time.time()
                data['elapsed_seconds']=time.perf_counter()-started;data['requests']=dict(c.requests);self.save(data)
                self.progress.update(phase=data['phase'])
        except Exception:
            data['phase']='Needs attention';self.save(data);raise
        finally:c.close()

    def start(self,confirmed_count):
        if self.active:raise SafetyError('Run already active.')
        self.active=True;self.stop.clear()
        def work():
            try:self.execute(confirmed_count)
            except SafetyError as e:self.progress={'phase':'Needs attention','error':str(e)}
            except Exception:self.progress={'phase':'Needs attention','error':'Unexpected failure; reconcile the saved run before continuing.'}
            finally:self.active=False
        self.thread=threading.Thread(target=work,daemon=True);self.thread.start()
