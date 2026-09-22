"""Shared read-only navigation, application discovery and comparison components."""
import json
import sqlite3
import time
from pathlib import Path
import streamlit as st
from cleanup import Client, SafetyError, uid

STEPS=('Select','Analyze','Review','Execute','Results')


def navigate(label):st.session_state['workspace_tab']=label


def scope(cfg):
    return (cfg.org,cfg.instance,cfg.user_instance) if cfg else None


def find_applications(client, query, os_type):
    results={}
    for page in range(1,101):
        body={'pageNumber':page,'pageSize':100,'searchText':query.strip(),'searchBy':'app','orderBy':'name',
              'isAscending':True,'includeMaster':False,'permittedApplications':False,'isBuiltInApplication':False,
              'isHidden':False,'isTemporary':False,'category':0,'osType':os_type,'includeChildOrganizations':False,
              'countries':[],'categories':[],'isMaintained':False,'getMaintained':False}
        rows=client.post_read('/Application/ApplicationGetByParameters',body)
        if not isinstance(rows,list):raise SafetyError('Application search returned an unexpected response.')
        if not rows:return sorted(results.values(),key=lambda r:(r['name'].lower(),r['applicationId']))
        for r in rows:
            aid=uid(r.get('applicationId'))
            if aid in results:raise SafetyError('Application search repeated IDs across pages; narrow the search.')
            if uid(r.get('organizationId'))!=client.cfg.org or r.get('osType')!=os_type or r.get('isBuiltIn') is not False:
                raise SafetyError('Application search returned an unexpected owner, OS or built-in application.')
            results[aid]={'applicationId':aid,'name':str(r.get('name') or 'Unnamed application'),'osType':os_type}
    raise SafetyError('Search exceeds 10,000 applications; narrow the search.')


def stepper(current):
    current=max(0,min(4,current))
    parts=[]
    for i,label in enumerate(STEPS):
        color='#007f9d' if i==current else '#dbe3e7'
        parts.append(f'<div style="flex:1;min-width:100px;padding:10px;border-bottom:3px solid {color};color:#244654">'
                     f'{"✓" if i<current else str(i+1)} · <b>{label}</b></div>')
    st.html('<div style="display:flex;flex-wrap:wrap;background:#f7fafb;margin-bottom:16px">'+''.join(parts)+'</div>')
    st.caption(f'Current step: {STEPS[current]}')


def picker(cfg,key,multiple=False):
    """Only an explicit selection feeds cleanup scope; names never identify writes."""
    query=st.text_input('Search application names',key=key+'_query',placeholder='Adobe, Blender, or a test application')
    os_label=st.selectbox('Application operating system',['Windows','macOS'],key=key+'_os')
    result_key=key+'_results'
    if st.button('Search applications',key=key+'_search',disabled=cfg is None):
        client=Client(cfg)
        try:
            with st.spinner('Searching current customer applications…'):
                rows=find_applications(client,query,1 if os_label=='Windows' else 2)
            st.session_state[result_key]={'scope':scope(cfg),'rows':rows,'loaded':time.time(),'query':query,'os':os_label}
        except SafetyError as e:
            st.session_state.pop(result_key,None);st.error(str(e))
        finally:client.close()
    saved=st.session_state.get(result_key,{})
    rows=saved.get('rows',[]) if cfg and saved.get('scope')==scope(cfg) else []
    lookup={r['applicationId']:r for r in rows}
    hints={r['Application ID']:r['Reported hashes'] for r in st.session_state.get('large_rows',[])} if st.session_state.get('large_scope')==scope(cfg) else {}
    def label(aid):
        r=lookup[aid];count=f"{hints[aid]:,} reported hashes" if aid in hints else 'count not loaded'
        return f"{r['name']} · {'Windows' if r['osType']==1 else 'macOS'} · {count} · {aid}"
    if rows:
        st.caption(f"{len(rows):,} applications · {saved['os']} search ‘{saved['query']}’ · loaded {time.strftime('%H:%M:%S',time.localtime(saved['loaded']))}")
        if multiple:return st.multiselect('Choose applications to scan',list(lookup),format_func=label,key=key+'_selected')
        return st.selectbox('Choose an application',list(lookup),format_func=label,index=None,key=key+'_selected')
    if saved and saved.get('scope')==scope(cfg):st.info('No matching applications. Try another name or operating system.')
    return [] if multiple else None


def comparison(before,removed,added=0,preserved=None,complete=False):
    after=before-removed+added
    left,right=st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown('**Before · saved source snapshot**');st.metric('Original records',f'{before:,}')
            st.caption(f'{removed:,} records selected for removal')
    with right:
        with st.container(border=True):
            st.markdown('**After · verified at completion**' if complete else '**After · expected result**')
            st.metric('Resulting records',f'{after:,}',delta=f'{after-before:+,} records',delta_color='inverse')
            st.caption(f'{added:,} replacement rules · {before-removed if preserved is None else preserved:,} preserved records')
    if before:st.caption(f'{(before-after)/before:.1%} record reduction · Record counts do not measure security equivalence.')


def history_rows(cfg,root):
    if not cfg:return []
    expected={'org':cfg.org,'instance':cfg.instance,'user_instance':cfg.user_instance};rows=[]
    for p in Path(root).glob('*/cleanup.sqlite3'):
        try:
            db=sqlite3.connect(p.resolve().as_uri()+'?mode=ro',uri=True)
            try:
                meta={k:json.loads(v) for k,v in db.execute('SELECT key,value FROM meta')}
                if meta.get('scope')!=expected:continue
                statuses=dict(db.execute('SELECT status,COUNT(*) FROM targets GROUP BY status'))
                apps=[json.loads(r[0]) for r in db.execute('SELECT body FROM apps')]
            finally:db.close()
            rows.append({'Run':p.parent.name,'Workflow':'Duplicate hashes','Status':meta.get('phase','Preview'),
                'Application':', '.join(a.get('name','') for a in apps),'Application IDs':', '.join(a.get('applicationId','') for a in apps),
                'Planned':sum(statuses.values()),'Verified':statuses.get('VerifiedAbsent',0),'Created':meta.get('created',0),'directory':str(p.parent)})
        except (ValueError,sqlite3.Error,OSError):continue
    for p in Path(root).glob('*/consolidation.json'):
        try:
            from consolidation import read_journal
            data=read_journal(p)
            if data['scope']!=expected:continue
            rows.append({'Run':p.parent.name,'Workflow':'Conditional rules','Status':data['phase'],
                'Application':data['metadata']['name'],'Application IDs':data['app'],'Planned':len(data['plan']['targets']),
                'Verified':sum(s=='Verified' for s in data['deletions'].values()),'Created':data['created'],'directory':str(p.parent)})
        except (ValueError,KeyError,OSError):continue
    return sorted(rows,key=lambda r:r['Created'],reverse=True)


def activity(cfg):
    @st.fragment(run_every='2s')
    def status():
        for key,label in [('run','Duplicate cleanup'),('consolidation_run','Conditional-rule cleanup')]:
            run=st.session_state.get(key)
            if not run or not run.active:continue
            with st.container(border=True):
                st.write(f"**{label} is running** · {run.progress.get('phase','Working')}")
                st.caption(f'Organization {run.cfg.org} · {run.directory.name} · Last status refresh {time.strftime("%H:%M:%S")}')
                if st.button('Request stop',key='global_stop_'+key):run.stop.set()
                st.caption('The current requests finish before stopping. Verified results are saved for recovery.')
    status()


def overview(cfg):
    from insights import report_summary
    st.subheader('Application health overview')
    st.caption('Loaded reports and selected runs for this connection. These are not a complete organization inventory.')
    candidates=st.session_state.get('candidates',[]) if cfg and st.session_state.get('candidate_org')==cfg.org else []
    summary=report_summary(candidates)
    large=st.session_state.get('large_rows',[]) if cfg and st.session_state.get('large_scope')==scope(cfg) else []
    verified=0
    for key in ('run','consolidation_run'):
        run=st.session_state.get(key)
        if not run or scope(run.cfg)!=scope(cfg):continue
        try:
            audit=run.audit()
            verified+=audit['counts']['verified'] if key=='run' else sum(v=='Verified' for v in audit['deletions'].values())
        except (OSError,ValueError,KeyError):continue
    a,b,c,d=st.columns(4)
    a.metric('Applications in duplicate report',len(summary['applications']))
    b.metric('Reported duplicate groups',summary['groups'])
    c.metric('Reported applications >1,000 hashes',sum(r['Reported hashes']>1000 for r in large))
    d.metric('Verified removals in loaded runs',f'{verified:,}')
    st.markdown('**Choose your next step**')
    left,right=st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown('**Remove duplicate hashes**')
            st.write('Open Report and preview to select applications. Review the retained IDs in Execution and audit before deleting redundant copies.')
            st.button('Open duplicate cleanup',on_click=navigate,args=('Report and preview',),type='primary')
    with right:
        with st.container(border=True):
            st.markdown('**Consolidate application records**')
            st.write('Open Application cleanup to search by name, analyze hash observations, and review proposed conditional rules. Large applications helps prioritize the work.')
            st.button('Open application cleanup',on_click=navigate,args=('Application cleanup',),type='primary')
    st.button('View large-application report',on_click=navigate,args=('Large applications',))
    st.caption('Report estimates are refreshed explicitly. Every execution revalidates its saved preview against current application records.')
