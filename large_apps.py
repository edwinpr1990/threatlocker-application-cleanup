"""Read-only large-application report, with explicit reported/live distinction."""
import csv
import io
import json
import re
from cleanup import SafetyError, uid

REPORT_ID = '4277aabc-94fe-4b3e-a336-9af0128e116a'
REPORT_NAME = 'Applications with more than a Thousand Hashes'


def parse(content, filename, org):
    try:
        text = content.decode('utf-8-sig')
        data = json.loads(text) if filename.lower().endswith('.json') else list(csv.DictReader(io.StringIO(text)))
        rows = data.get('data') if isinstance(data, dict) else data
        if not isinstance(rows, list): raise ValueError()
        result = {}
        for row in rows:
            r = {re.sub('[^a-z0-9]', '', k.lower()): v for k,v in row.items()}
            if uid(r['organizationid']) != uid(org):
                raise SafetyError('Report contains another organization.')
            aid = uid(r['applicationid'])
            raw = str(r['countofhashes']).replace(',', '')
            if not raw.isdigit(): raise ValueError()
            item = {'Application':str(r.get('name','')), 'Application ID':aid, 'Reported hashes':int(raw)}
            if aid in result and result[aid] != item:
                raise SafetyError('Conflicting repeated application rows; refresh the report.')
            result[aid] = item
        return sorted(result.values(), key=lambda r:(-r['Reported hashes'],r['Application ID']))
    except SafetyError: raise
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        raise SafetyError('Expected ApplicationId, Name, OrganizationId, and Count of Hashes columns.') from None


def render(cfg):
    import streamlit as st
    import pandas as pd
    from cleanup import Client, primary
    from portal_theme import application_chart, CYAN
    from datetime import datetime
    st.subheader('Large application health')
    st.caption('Find applications worth reviewing, then validate their current records before choosing a cleanup.')
    scope = (cfg.org,cfg.instance,cfg.user_instance) if cfg else None
    with st.expander('Load or refresh large-application report', expanded=st.session_state.get('large_scope')!=scope or not st.session_state.get('large_rows')):
        st.write(REPORT_NAME)
        if st.button('Generate large-application report', disabled=cfg is None):
            c=Client(cfg)
            try:
                with st.spinner('Loading reported application sizes…'):
                    data=c.report(REPORT_ID)
                    st.session_state['large_rows']=parse(json.dumps(data).encode(),'report.json',cfg.org)
                    st.session_state['large_scope']=scope
                    st.session_state['large_time']=datetime.now().isoformat(timespec='seconds')
                    st.session_state['large_live']={}
            except SafetyError as e: st.error(str(e))
            finally:c.close()
        upload=st.file_uploader('Upload large-application report',type=['json','csv'],key='large_upload')
        if st.button('Load large-application export',disabled=cfg is None or upload is None):
            try:
                st.session_state['large_rows']=parse(upload.getvalue(),upload.name,cfg.org)
                st.session_state['large_scope']=scope
                st.session_state['large_time']=datetime.now().isoformat(timespec='seconds')
                st.session_state['large_live']={}
            except SafetyError as e:st.error(str(e))
    if not cfg or st.session_state.get('large_scope')!=scope:
        st.info('Connect to a customer and load the report to see application sizes.');return
    rows=st.session_state.get('large_rows',[])
    st.caption('Loaded '+st.session_state.get('large_time','')+' · Report counts may lag live records. They are not duplicate counts or deletion targets.')
    search=st.text_input('Find a large application',placeholder='Application name or ID')
    rows=[r for r in rows if search.lower() in (r['Application']+' '+r['Application ID']).lower()]
    a,b,c,d=st.columns(4)
    a.metric('Applications >1,000',sum(r['Reported hashes']>1000 for r in rows))
    b.metric('Reported hashes',f"{sum(r['Reported hashes'] for r in rows):,}")
    c.metric('Largest application',f"{max([r['Reported hashes'] for r in rows],default=0):,}")
    d.metric('Applications >100,000',sum(r['Reported hashes']>100000 for r in rows))
    if not rows:st.info('No applications match this report/filter.');return
    application_chart(rows[:12],[('Reported hashes',CYAN)])
    live=st.session_state.get('large_live',{})
    display=[dict(r,**live.get(r['Application ID'],{})) for r in rows]
    frame=pd.DataFrame(display)
    for col in ('Reported hashes','Live records','Live hash records','Live distinct hashes'):
        if col in frame:frame[col]=frame[col].astype('Int64')
    st.dataframe(frame,width='stretch',hide_index=True)
    st.download_button('Download application health CSV',frame.to_csv(index=False).encode(),'application-health.csv','text/csv')
    choices={r['Application ID']:r['Application'] for r in rows}
    selected=st.selectbox('Application to inspect',list(choices),format_func=lambda a:f'{choices[a]} · {a}',index=None,key='large_selected')
    st.caption('Live inspection reads every record in the selected application. Million-record applications may take substantial time and memory.')
    if st.button('Verify selected application counts',disabled=not selected):
        client=Client(cfg)
        try:
            with st.spinner('Counting live records across all pages…'):
                metadata=client.metadata(selected)
                records=list(client.files(selected))
                hashes=[primary(r) for r in records if primary(r)]
                live[selected]={'Live records':len(records),'Live hash records':len(hashes),'Live distinct hashes':len(set(hashes)),
                    'OS':'Windows' if metadata['osType']==1 else 'macOS','Verified at':datetime.now().isoformat(timespec='seconds')}
                st.session_state['large_live']=live
            st.rerun()
        except SafetyError as e:st.error(str(e))
        finally:client.close()
    if selected:
        def use_application():
            st.session_state['consolidation_app']=selected
            st.session_state['workspace_tab']='Application cleanup'
        st.button('Use selected application for conditional-rule preview',on_click=use_application)
        st.caption('Opens Application cleanup with this ID selected. No records change until you review and apply a preview.')
