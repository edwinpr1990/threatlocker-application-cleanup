"""Guided conditional-rule cleanup, using the portal dashboard's existing styles."""
import json
import time
import uuid
from pathlib import Path
import pandas as pd
import streamlit as st
from cleanup import SafetyError,uid
from consolidation import ConsolidationRun
from guided_ui import picker,stepper,comparison


def render(cfg,root):
    st.subheader('Application cleanup')
    st.caption('Review hash observations → inspect conditional rules → apply to the same application → verify every removal.')
    st.info('Conditional rules can match files beyond the original hashes. Observation coverage is not security equivalence. Review every proposed path and identity condition before applying.')
    active=st.session_state.get('consolidation_run')
    phase=active.audit()['phase'] if active and active.path.exists() else ''
    stepper(3 if active and active.active else 4 if phase=='Complete' else 2 if phase else 0)
    with st.expander('1 · Choose an application',expanded=active is None):
        picked=picker(cfg,'conditions_picker')
        if picked:
            def use_picked():st.session_state['consolidation_app']=picked
            st.button('Use this application',on_click=use_picked)
        app=st.text_input('Application ID for conditional-rule cleanup',value=st.session_state.get('large_selected') or '',key='consolidation_app')
        profile=st.selectbox('Rule suggestion profile',['Conservative','Balanced','Aggressive'],help='Changes candidate generation only. Independent coverage and safety checks still apply.')
        st.caption('Existing custom rules and hashes without usable observations are preserved. This workflow does not clone applications or move policies.')
        if st.button('Build conditional-rule preview',type='primary',disabled=cfg is None or bool(active and active.active)):
            try:
                aid=uid(app)
                new=ConsolidationRun(cfg,root/'runs'/('conditions-'+time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6]))
                with st.spinner('Reading application records and generating reviewed candidates…'):new.prepare(aid,profile.lower())
                st.session_state['conditions_reviewed']=False
                st.session_state['conditions_confirm']=''
                st.session_state['consolidation_run']=new;active=new
            except SafetyError as e:st.error(str(e))
    with st.expander('Resume a saved conditional-rule run'):
        paths=[]
        if cfg:
            for p in sorted((root/'runs').glob('*/consolidation.json'),reverse=True):
                try:
                    candidate=ConsolidationRun(cfg,p.parent)
                    if candidate.audit()['scope']==candidate.scope():paths.append(p.parent)
                except (ValueError,KeyError,OSError):continue
        saved=st.selectbox('Conditional-rule run',paths,index=None,format_func=lambda p:p.name)
        if st.button('Load conditional-rule run',disabled=not saved or bool(active and active.active)):
            active=ConsolidationRun(cfg,saved);st.session_state['consolidation_run']=active
            st.session_state['conditions_reviewed']=False
            st.session_state['conditions_confirm']=''
    if active is None:
        st.info('Start with an application ID, or select one in Large applications. A preview makes no changes.');return
    try:data=active.audit()
    except (ValueError,OSError):st.error('Unable to read the saved preview.');return
    plan=data['plan'];target_count=len(plan['targets']);rule_count=len(plan['rules'])
    same=bool(cfg and data['scope']=={'org':cfg.org,'instance':cfg.instance,'user_instance':cfg.user_instance})
    st.write(f"**{data['metadata']['name']}** · {data['app']}")
    st.caption(f"Preview created {time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(data['created']))} · Organization {data['scope']['org']} · {data['plan']['profile'].title()} profile. Current records are checked again before writes.")
    if app.strip() and app.strip()!=data['app']:st.info('The application selection has changed. Build a new preview to replace the saved application shown below.')
    comparison(plan['source_count'],target_count,rule_count,len(plan['fallback']),data['phase']=='Complete')
    a,b,c,d=st.columns(4)
    a.metric('Source records (snapshot)',f"{plan['source_count']:,}")
    b.metric('Proposed conditional rules',f'{rule_count:,}')
    c.metric('Covered hash records',f'{target_count:,}')
    d.metric('Preserved records',f"{len(plan['fallback']):,}")
    if target_count:
        st.caption(f"Projected result: {plan['source_count']-target_count+rule_count:,} records · {target_count-rule_count:,} fewer records. Applies only to the reviewed application ID.")
    st.markdown('**2 · Review the proposed conditions**')
    if plan['reviews']:st.dataframe(plan['reviews'],width='stretch',hide_index=True)
    else:st.info('No eligible conditional-rule candidates. Hashes and existing rules are preserved.')
    for i,rule in enumerate(plan['rules']):
        with st.expander(f"Rule {i+1} · {len(rule['source_ids']):,} covered hash records"):
            st.json(rule['fields'])
            ids=set(rule['source_ids'])
            st.dataframe([r for r in plan['targets'] if str(r['applicationFileId']) in ids],width='stretch',hide_index=True)
    with st.expander('Covered IDs and preserved records'):
        st.write('Covered source records');st.dataframe(plan['targets'],width='stretch',hide_index=True)
        st.write('Preserved source records');st.dataframe(plan['fallback'],width='stretch',hide_index=True)
    st.download_button('Download conditional-rule review',json.dumps(data,indent=2).encode(),'conditional-rule-review.json','application/json')
    if plan['reviews']:st.download_button('Download proposed rules CSV',pd.DataFrame(plan['reviews']).to_csv(index=False).encode(),'proposed-conditions.csv','text/csv')
    st.markdown('**3 · Apply and verify**')
    if not same:st.warning('Reconnect to the organization and API instance used for this preview.')
    if target_count and data['phase']!='Complete':
        reviewed=st.checkbox('I reviewed the proposed conditions and accept their broader matching scope',key='conditions_reviewed',disabled=active.active)
        confirmation=st.text_input(f'Type APPLY {target_count} to replace the covered hash records',key='conditions_confirm',disabled=active.active)
        if st.button('Apply reviewed conditional rules',type='primary',disabled=not same or (bool(app.strip()) and app.strip()!=data['app']) or active.active or not reviewed or confirmation!=f'APPLY {target_count}'):
            active=ConsolidationRun(cfg,active.directory);st.session_state['consolidation_run']=active
            active.start(target_count);st.rerun()

    was_active=active.active
    @st.fragment(run_every=1 if was_active else None)
    def monitor():
        audit=active.audit();verified=sum(v=='Verified' for v in audit['deletions'].values())
        inserts=sum(i['status']=='Verified' for i in audit['insertions'])
        st.write(active.progress.get('phase') if active.active else audit['phase'])
        st.progress(inserts/max(rule_count,1),text=f'{inserts:,} / {rule_count:,} replacement rules verified')
        st.progress(verified/max(target_count,1),text=f'{verified:,} / {target_count:,} covered hash deletions verified')
        if active.progress.get('error'):st.error(active.progress['error'])
        if active.active:
            if st.button('Stop after current request',key='stop_conditions'):active.stop.set()
        elif audit['phase']=='Complete':st.success('Saved verification passed: preserved records and replacement rules matched the expected result at completion.')
        if audit['events']:st.dataframe(audit['events'][-10:][::-1],width='stretch',hide_index=True)
        st.download_button('Download latest consolidation audit',json.dumps(audit,indent=2).encode(),'consolidation-audit.json','application/json',key='conditions_audit')
        if was_active and not active.active:st.rerun()
    monitor()
