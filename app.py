"""Local single-operator Streamlit UI. Each browser session supplies its connection."""
import json
import hashlib
import time
import uuid
from datetime import datetime
from pathlib import Path

import streamlit as st
import pandas as pd
from cleanup import Client, Run, Settings, SafetyError, REPORT_ID, parse_report, uid
from insights import report_summary, run_summary, deletion_progress

st.set_page_config(page_title='ThreatLocker Duplicate Cleanup',page_icon='🧹',layout='wide')
ROOT=Path(__file__).resolve().parent
RUNS=ROOT/'runs'
st.title('Application hash health')
st.caption('Understand duplicate records, review a safe cleanup plan, and track verified results.')

with st.sidebar:
    st.header('Customer connection')
    customer=st.text_input('Customer label',key='customer')
    org=st.text_input('Organization ID',key='org')
    c1,c2=st.columns(2)
    instance=c1.text_input('API instance',value='d',max_chars=1)
    user_instance=c2.text_input('UserInstance',value='D',max_chars=1)
    token=st.text_input('Authorization header value',type='password',key='token',help='Kept in this process/session only; never saved in audit files.')
    with st.expander('Advanced connection settings'):
        workers=st.slider('Maximum concurrent requests',1,8,4)
        page_size=st.selectbox('Full scan page size',[100,500,1000,5000,10000],index=2)
    st.caption('Run locally on 127.0.0.1. Use a separate local session for each customer.')
    if st.button('Disconnect / clear credentials'):
        active=st.session_state.get('run')
        if active and active.active:
            active.stop.set();st.warning('Stopping. Disconnect after the current requests finish.')
        else:
            st.session_state.clear();st.rerun()

try:
    cfg=Settings(org=uid(org),token=token,instance=instance.lower(),user_instance=user_instance,
                 workers=workers,page_size=page_size,mode='Bulk')
    cfg.validate()
except SafetyError:
    cfg=None

with st.sidebar:
    if cfg:st.success('Settings ready')
    else:st.info('Enter an organization ID and authorization value to begin.')
    st.caption('Settings are validated locally. Generate a report or preview to verify API access.')

for col,title,description in zip(st.columns(3),['1 · Discover','2 · Review','3 · Verify'],[
    'Load a report and choose applications.','Validate live records before any deletion.','Execute a reviewed plan and download the audit.']):
    with col.container(border=True):
        st.markdown(f'**{title}**');st.caption(description)

tabs=st.tabs(['Report and preview','Execution and audit','Run history'])
with tabs[0]:
    st.subheader('Discover duplicate candidates')
    st.caption('Start with a current ThreatLocker report or an exported CSV / JSON file. Loading a report does not change any records.')
    with st.expander('Report settings and coverage'):
        report_id=st.text_input('Predefined report ID',value=REPORT_ID)
        st.info('Applications Containing Same Hash omitted macOS in live testing. Add application IDs below to scan missing applications. Report data has no OS field; the OS filter is applied during live validation.')
        st.write('A hash appearing in different applications is legitimate. Cleanup always keeps a separate copy in each application.')
    if st.button('Generate current ThreatLocker report',disabled=cfg is None):
        client=Client(cfg)
        try:
            with st.spinner('Generating report…'):
                data=client.report(report_id)
                rows,repeated=parse_report(json.dumps(data).encode(),'report.json',cfg.org)
                st.session_state['candidates']=rows
                st.session_state['candidate_org']=cfg.org
                st.session_state['report_bytes']=json.dumps(data,indent=2).encode()
                st.session_state['report_info']={'source':'ThreatLocker API','loaded':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'repeated':repeated}
                st.success(f'{len(rows)} candidate groups; {repeated} repeated rows collapsed.')
        except SafetyError as exc:st.error(str(exc))
        finally:client.close()
    upload=st.file_uploader('Upload exported report (CSV or JSON)',type=['csv','json'])
    upload_id=(cfg.org,hashlib.sha256(upload.getvalue()).hexdigest()) if upload and cfg else None
    if upload_id and upload_id!=st.session_state.get('loaded_upload'):
        try:
            rows,repeated=parse_report(upload.getvalue(),upload.name,cfg.org)
            st.session_state['candidates']=rows;st.session_state['candidate_org']=cfg.org
            st.session_state['report_bytes']=json.dumps({'data':rows},indent=2).encode()
            st.session_state['loaded_upload']=upload_id
            st.session_state['report_info']={'source':upload.name,'loaded':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'repeated':repeated}
            st.caption(f'{len(rows)} candidate groups; {repeated} repeated rows collapsed.')
        except SafetyError as exc:
            st.session_state.pop('candidates',None);st.session_state.pop('candidate_org',None)
            st.error(str(exc))
    candidates=st.session_state.get('candidates',[]) if cfg and st.session_state.get('candidate_org')==cfg.org else []
    if candidates:
        info=st.session_state.get('report_info',{})
        st.caption(f"Source: {info.get('source','Previously loaded report')} · Loaded locally: {info.get('loaded','—')} · Repeated rows collapsed: {info.get('repeated',0)}")
    else:
        st.info('No report candidates loaded. Generate or upload a report, or expand the application scan below to enter application IDs directly.')
    if 'report_bytes' in st.session_state and cfg and st.session_state.get('candidate_org')==cfg.org:
        st.download_button('Download report JSON',st.session_state['report_bytes'],'threatlocker-report.json')
    st.subheader('Choose your scope')
    choices=sorted({r['ApplicationId'] for r in candidates})
    names={r['ApplicationId']:r.get('Name','') for r in candidates}
    selected=st.multiselect('Applications from report',choices,default=choices,format_func=lambda a:f'{names[a]} · {a}')
    operating=st.multiselect('Operating systems',['Windows','macOS'],default=['Windows','macOS'])
    with st.expander('Scan additional applications, including macOS'):
        st.caption('Use this when an application is missing from the report. Its current records will be scanned for duplicates.')
        extra=st.text_area('Additional application IDs to scan',help='One UUID per line. This explicitly expands the preview to these applications, including macOS.')
    scoped=[r for r in candidates if r['ApplicationId'] in selected]
    summary=report_summary(scoped)
    if scoped:
        st.subheader('Report overview')
        a,b,c,d=st.columns(4)
        a.metric('Applications in selection',len(summary['applications']))
        b.metric('Candidate hash groups',summary['groups'],help='One group is one application ID + hash. The same hash in two applications counts as two groups.')
        c.metric('Distinct hashes',summary['hashes'])
        d.metric('Estimated extra records',f"{summary['extras']:,}" if not summary['unknown_counts'] else f"≥ {summary['extras']:,}",help='Sum of Count minus one for known report counts. This is an estimate, not an approved deletion count.')
        st.caption(f"Report estimates only · {summary['shared_hashes']} hashes appear in multiple selected applications · {summary['unknown_counts']} groups have an unavailable count. OS filters take effect in the live preview.")
        chart,details=st.columns([3,2])
        with chart:
            st.markdown('**Where the reported duplicates are**')
            ranked=summary['applications'][:15]
            frame=pd.DataFrame([{'Application':r['Application']+' · '+r['Application ID'][:8],'Estimated extra records':r['Estimated extra records']} for r in ranked])
            st.bar_chart(frame.set_index('Application'),horizontal=True,color='#4F8BF9',height=max(200,min(450,len(ranked)*45)))
            st.caption('Top 15 applications by known estimated extra records. Full IDs are listed below.')
        with details:
            st.markdown('**What happens next**')
            st.write('Live validation checks application ownership, rule fields and every current record. It separates eligible duplicates from stale candidates and ambiguous rules.')
            st.write('The lowest numeric record ID is kept in each equivalent group. No records are deleted while building a preview.')
        st.dataframe(summary['applications'],width='stretch',hide_index=True)
        with st.expander('Inspect report rows'):
            st.dataframe(scoped,width='stretch',hide_index=True)
    st.caption('Report counts are hints. The preview reads current records and excludes missing, singleton, and ambiguous groups. Lowest numeric file ID survives; differing notes are archived.')
    active=st.session_state.get('run')
    if st.button('Build dry-run preview',type='primary',disabled=cfg is None or bool(active and active.active)):
        try:
            apps=[uid(a.strip()) for a in extra.splitlines() if a.strip()]
            if not scoped and not apps:raise SafetyError('Select report candidates or enter application IDs.')
            directory=RUNS/(time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
            run=Run(cfg,directory);st.session_state['run']=run
            run.start('prepare',scoped,apps,tuple(1 if os=='Windows' else 2 for os in operating))
            st.success('Live validation started. Open Execution and audit to follow progress and review your plan.')
        except SafetyError as exc:st.error(str(exc))

with tabs[1]:
    st.subheader('Cleanup plan and results')
    @st.fragment(run_every='2s')
    def monitor():
        run=st.session_state.get('run')
        if not run:
            st.info('Your plan will appear here. In Report and preview, choose applications and select Build dry-run preview. You can also restore an earlier run from Run history.');return
        st.write(f'Run: `{run.directory.name}`')
        st.write(f"**Status:** {run.progress.get('phase','Idle')}")
        if run.progress.get('error'):st.error(run.progress['error'])
        if run.progress.get('application'):st.caption(f"Application: {run.progress['application']}")
        if not (run.directory/'cleanup.sqlite3').exists():return
        audit=run.audit();counts=audit['counts']
        saved_scope=audit['metadata'].get('scope',{})
        connection_matches=bool(cfg and saved_scope=={'org':cfg.org,'instance':cfg.instance,'user_instance':cfg.user_instance})
        st.caption(f"Saved organization: {saved_scope.get('org','—')} · API instance: {saved_scope.get('instance','—')}")
        if not connection_matches:st.warning('This run belongs to a different or disconnected connection. Match its organization and API instance to resume it.')
        apps=run_summary(run.directory)
        a,b,c,d=st.columns(4)
        a.metric('Validated applications',len(apps));b.metric('Planned deletions',f"{counts['planned']:,}");c.metric('Verified absent',f"{counts['verified']:,}");d.metric('Preserved / stale groups',counts['skipped_groups'])
        progress=deletion_progress(audit)
        if progress['total']:
            with st.container(border=True):
                st.markdown('**Live deletion progress**')
                total=progress['total']
                st.progress(progress['accepted']/total,text=f"Deletion requests accepted or already verified: {progress['accepted']:,} / {total:,}")
                st.progress(progress['verified']/total,text=f"Independently verified absent: {progress['verified']:,} / {total:,}")
                st.caption('The first bar advances as successful record responses arrive. The second advances after full application reads confirm absence. HTTP acceptance alone is not proof of deletion.')
                st.caption(f"Queued: {progress['queued']:,} · Dispatched / outcome pending: {progress['dispatched']:,} · Needs reconciliation: {progress['attention']:,}")
                if run.active:
                    phase=run.progress.get('phase','Working')
                    message='Reading current application records to independently verify results.' if phase=='Reconciling' else 'Processing the plan; requests and safety checks run in bounded batches.'
                    with st.status(f'{phase} — operation running',state='running',expanded=True):
                        st.write(message)
                        st.caption('This panel refreshes every 2 seconds. A safety check, network timeout, or rate-limit cooldown can pause record updates; the running indicator alone does not confirm API progress.')
                    starts=[e['time'] for e in audit['events'] if e['kind']=='ExecutionStarted']
                    if starts:st.caption(f"Elapsed since latest execution started: {max(0,int(time.time()-starts[-1])):,} seconds")
                if progress['recent']:
                    age=max(0,int(time.time()-progress['recent'][0]['Time']))
                    st.caption(f'Last recorded deletion response: {age:,} seconds ago' if run.active else 'Most recent recorded deletion responses')
                    recent=[dict(r,Time=datetime.fromtimestamp(r['Time']).strftime('%H:%M:%S')) for r in progress['recent']]
                    st.dataframe(recent,width='stretch',hide_index=True)
                elif run.active:st.caption('No deletion responses yet. Initial validation may still be running.')
                if progress['attention']:st.warning('Some records need reconciliation. Their outcomes are not counted as successful deletion requests.')
                names={a['Application ID']:a['Application'] for a in apps}
                with st.expander('Progress for each application',expanded=run.active):
                    for item in progress['applications']:
                        st.write(f"**{names.get(item['app'],'Application')}** · `{item['app']}`")
                        st.progress(item['accepted']/item['total'],text=f"{item['accepted']:,} / {item['total']:,} accepted or verified · {item['verified']:,} verified absent · {item['attention']:,} need reconciliation")
        st.caption(f"Accepted, awaiting verification: {counts['statuses'].get('Accepted',0)} · Uncertain responses: {counts['statuses'].get('Uncertain',0)} · Still present after reconciliation: {counts['statuses'].get('StillPresent',0)}")
        if apps:
            left,right=st.columns([3,2])
            with left:
                st.markdown('**Cleanup by application**')
                chart=pd.DataFrame([{'Application':r['Application']+' · '+r['Application ID'][:8],
                    'Verified deleted':r['Verified deletions'],'Still to verify':r['Remaining planned']} for r in apps])
                st.bar_chart(chart.set_index('Application'),horizontal=True,color=['#31B6A1','#4F8BF9'],height=max(180,min(400,len(apps)*60)))
            with right:
                before=sum(r['Baseline records'] for r in apps);planned=counts['planned']
                st.metric('Baseline records',f'{before:,}')
                st.metric('Expected after full cleanup',f'{before-planned:,}')
                st.caption(f'{planned/before:.1%} of baseline records are planned for removal.' if before else 'No baseline records.')
                st.caption('Expected totals are a plan, not a fresh record count. Only verified deletions are confirmed absent.')
            st.dataframe(apps,width='stretch',hide_index=True)
        preview=run.preview()
        reasons={}
        for group in preview:
            if group['survivor'] is None:reasons[group['reason']]=reasons.get(group['reason'],0)+1
        if reasons:
            with st.expander('Why some groups were preserved or skipped'):
                for reason,total in reasons.items():st.write(f'**{total} groups:** {reason}')
        with st.expander('Review hash groups and retained record IDs',expanded=bool(counts['remaining'])):
            st.dataframe(preview,width='stretch',hide_index=True)
        with st.expander('Planned record IDs and results'):
            st.dataframe(audit['targets'],width='stretch',hide_index=True)
        st.caption('Verify application IDs and survivor IDs. Key-file differences or custom matching rules preserve the entire hash group.')
        if run.active:
            if st.button('Stop after in-flight requests'):run.stop.set()
            return
        st.download_button('Download audit JSON',json.dumps(audit,indent=2),'cleanup-audit.json')
        import csv,io
        output=io.StringIO();writer=csv.DictWriter(output,fieldnames=['app','fid','hash','status','detail'])
        writer.writeheader();writer.writerows(audit['targets'])
        st.download_button('Download record results CSV',output.getvalue(),'cleanup-results.csv')
        remaining=counts['remaining']
        prepared=audit['metadata'].get('prepared') is not None
        if not prepared:st.warning('This preview did not finish. Build a new preview before execution.')
        confirmation=''
        if prepared and remaining:
            st.warning(f'{remaining:,} records remain in this plan. Review the applications and retained IDs above before authorizing deletion.')
            confirmation=st.text_input(f'Type DELETE {remaining} to authorize this preview',key='confirm')
        elif prepared:
            st.success('All planned deletions are verified. Download the audit or build a fresh preview to check for new duplicates.' if counts['planned'] else 'No eligible duplicates found. No deletion is needed; preserved groups are explained above.')
        if st.button('Reconcile current records (read only)',disabled=not connection_matches or not prepared):
            restored=Run(cfg,run.directory);st.session_state['run']=restored
            restored.start('execute',0,True);st.rerun()
        if st.button('Delete reviewed duplicate records',type='primary',disabled=not connection_matches or not prepared or remaining==0 or confirmation!=f'DELETE {remaining}'):
            restored=Run(cfg,run.directory);st.session_state['run']=restored
            restored.start('execute',remaining);st.rerun()
    monitor()

with tabs[2]:
    st.subheader('Previous runs and recovery')
    st.caption('Original survivor IDs are never replaced on resume. Reconciliation checks complete manifests before retrying any remaining record.')
    history=[];history_rows=[]
    if cfg:
        for path in sorted(RUNS.glob('*/cleanup.sqlite3'),reverse=True):
            try:
                audit=Run(cfg,path.parent).audit()
                if audit['metadata'].get('scope',{})=={'org':cfg.org,'instance':cfg.instance,'user_instance':cfg.user_instance}:
                    history.append(path.parent)
                    history_rows.append({'Run':path.parent.name,'Status':audit['metadata'].get('phase','Incomplete preview'),
                        'Planned':audit['counts']['planned'],'Verified':audit['counts']['verified'],'Remaining':audit['counts']['remaining'],
                        'Created':datetime.fromtimestamp(audit['metadata'].get('created',0)).strftime('%Y-%m-%d %H:%M')})
            except Exception:continue
    if history_rows:st.dataframe(sorted(history_rows,key=lambda r:r['Created'],reverse=True),width='stretch',hide_index=True)
    else:st.info('No saved runs for this connection yet. Your first live preview creates a resumable audit journal.')
    selected_run=st.selectbox('Run directory',history,format_func=lambda p:p.name,index=None)
    if st.button('Load saved run',disabled=selected_run is None or bool(st.session_state.get('run') and st.session_state['run'].active)):
        st.session_state['run']=Run(cfg,selected_run)
        saved=st.session_state['run'].audit()
        phase='Complete · saved verification results' if saved['metadata'].get('phase')=='Complete' else 'Loaded; reconcile before resuming'
        st.session_state['run'].update(phase=phase);st.rerun()
