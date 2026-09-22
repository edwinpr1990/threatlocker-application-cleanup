"""Read-only dashboard summaries; report counts never feed deletion decisions."""
import json
from collections import Counter, defaultdict
from cleanup import open_db


def deletion_progress(audit):
    """Count distinct target IDs, not attempts; HTTP success is not verification."""
    targets=audit['targets'];statuses=Counter(t['status'] for t in targets)
    accepted=statuses['Accepted']+statuses['VerifiedAbsent']
    verified=statuses['VerifiedAbsent']
    by_app=defaultdict(list)
    for target in targets:by_app[target['app']].append(target)
    applications=[]
    for app,rows in sorted(by_app.items()):
        s=Counter(r['status'] for r in rows)
        applications.append({'app':app,'total':len(rows),'accepted':s['Accepted']+s['VerifiedAbsent'],
            'verified':s['VerifiedAbsent'],'attention':s['Uncertain']+s['StillPresent']})
    lookup={(r['app'],r['fid']):r for r in targets}
    recent=[]
    for event in reversed(audit['events']):
        if event['kind']!='DeleteResponse':continue
        target=lookup.get((event['app'],event['fid']),{})
        recent.append({'Time':event['time'],'Application ID':event['app'],'Record ID':event['fid'],
            'Response':event['detail'],'Current status':target.get('status','Unknown')})
        if len(recent)==10:break
    return {'total':len(targets),'accepted':accepted,'verified':verified,
        'queued':statuses['Planned'],'dispatched':statuses['Dispatched'],
        'attention':statuses['Uncertain']+statuses['StillPresent'],'applications':applications,'recent':recent}


def report_summary(rows):
    groups={}
    for r in rows:
        groups[(r['ApplicationId'],r['Hash'])]=r
    apps={}; owners=defaultdict(set); unknown=0
    for (app,h),r in groups.items():
        item=apps.setdefault(app,{'Application':r.get('Name') or 'Unnamed application','Application ID':app,
            'Candidate groups':0,'Estimated extra records':0,'Unknown counts':0})
        item['Candidate groups']+=1;owners[h].add(app)
        try:
            value=float(r.get('Count'))
            if not value.is_integer() or value<1:raise ValueError()
            item['Estimated extra records']+=int(value)-1
        except (TypeError,ValueError,OverflowError):
            item['Unknown counts']+=1;unknown+=1
    return {'applications':sorted(apps.values(),key=lambda x:(-x['Estimated extra records'],x['Application ID'])),
        'groups':len(groups),'hashes':len(owners),'shared_hashes':sum(len(a)>1 for a in owners.values()),
        'extras':sum(a['Estimated extra records'] for a in apps.values()),'unknown_counts':unknown}


def run_summary(directory):
    db=open_db(directory)
    try:
        rows=[]
        for app in db.execute('SELECT * FROM apps').fetchall():
            meta=json.loads(app['body']);aid=app['app']
            before=db.execute('SELECT COUNT(*) FROM baseline WHERE app=?',(aid,)).fetchone()[0]
            statuses=Counter({r[0]:r[1] for r in db.execute('SELECT status,COUNT(*) FROM targets WHERE app=? GROUP BY status',(aid,))})
            planned=sum(statuses.values());verified=statuses['VerifiedAbsent']
            groups=db.execute('SELECT COUNT(*) FROM groups WHERE app=? AND survivor IS NOT NULL',(aid,)).fetchone()[0]
            rows.append({'Application':meta.get('name','Unnamed application'),'Application ID':aid,
                'OS':{1:'Windows',2:'macOS'}.get(meta.get('osType'),'Unknown'),'Baseline records':before,
                'Eligible groups':groups,'Planned deletions':planned,'Verified deletions':verified,
                'Expected after cleanup':before-planned,'Remaining planned':planned-verified})
        return rows
    finally:db.close()
