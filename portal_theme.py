"""Portal-inspired presentation only; no API or cleanup behavior."""
import streamlit as st

CYAN='#00B1D6'
TEAL='#00425C'
GREEN='#3FB882'


def apply_theme():
    st.html('''<style>
    .stApp {font-family:Arial,Helvetica,sans-serif;}
    [data-testid="stMain"] {background:#e9ecef;}
    [data-testid="stMainBlockContainer"] {padding:4.5rem 1.4rem 3rem;max-width:1600px;}
    [data-testid="stHeader"] {background:#002e40;border-bottom:1px solid #164b5c;}
    [data-testid="stToolbar"] {color:#fff;}
    [data-testid="stSidebar"] {background:#00425c;border-right:1px solid #1a5368;}
    [data-testid="stSidebar"] h2,[data-testid="stSidebar"] label,
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"],
    [data-testid="stSidebar"] summary {color:#f2f8fa;}
    [data-testid="stSidebar"] [data-testid="stSidebarContent"] {padding-top:1.2rem;}
    [data-testid="stSidebar"] [data-testid="stExpander"] {border-color:#3a687a;}
    [data-testid="stSidebar"] [data-testid="stButton"] button {background:#07516b;color:white;border-color:#518094;}
    [data-testid="stSidebar"] [data-testid="stAlert"] {background:#e8f5f7;color:#174955;}
    [data-testid="stSidebar"] [data-testid="stAlert"] p {color:#174955;}
    [data-testid="stMain"] h1 {font-size:1.55rem;font-weight:650;color:#143d4d;letter-spacing:-.02em;}
    [data-testid="stMain"] h3 {font-size:1.13rem;font-weight:650;color:#143d4d;padding-top:.35rem;}
    [data-testid="stMain"] p,[data-testid="stMain"] label {font-size:.88rem;}
    [data-testid="stCaptionContainer"] p {font-size:.77rem!important;color:#526975!important;line-height:1.45;}
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {color:#c2dce5!important;}
    [data-testid="stMetric"] {background:#f8fafb;border:1px solid #dbe3e7;border-top:3px solid #00b1d6;border-radius:6px;padding:14px 16px;min-height:104px;}
    [data-testid="stMetricValue"] {font-size:2rem;color:#00425c;font-weight:650;}
    [data-testid="stMain"] [data-testid="stMetricValue"] p {font-size:2rem!important;color:#00425c;line-height:1.2;}
    [data-testid="stMetricLabel"] {color:#526874;}
    [data-baseweb="tab-list"] {gap:0;background:#fff;border:1px solid #dbe3e7;border-radius:6px 6px 0 0;padding:0 10px;}
    [data-baseweb="tab"] {height:46px;padding:0 22px;color:#536976;font-weight:600;}
    [data-baseweb="tab"][aria-selected="true"] {color:#006f89;background:#eef9fc;}
    [data-baseweb="tab-highlight"] {background:#00b1d6;height:3px;}
    [data-baseweb="tab-panel"] {background:#fff;border:1px solid #dbe3e7;border-top:0;border-radius:0 0 6px 6px;padding:20px;box-shadow:0 2px 3px #002e4009;}
    [data-testid="stExpander"] {border:1px solid #dbe3e7;border-radius:6px;}
    [data-testid="stMain"] [data-testid="stExpander"] summary {background:#f8f9fa;}
    [data-testid="stMain"] button {border-radius:6px;min-height:34px;font-size:.84rem;}
    [data-testid="stMain"] button[kind="primary"] {background:#007f9d;color:#fff;border:1px solid #007f9d;}
    [data-testid="stMain"] button[kind="primary"]:hover {background:#006780;border-color:#006780;}
    [data-testid="stMain"] button:focus-visible {outline:3px solid #00b1d6;outline-offset:2px;}
    [data-testid="stMain"] button:disabled {opacity:.5;}
    [data-testid="stDataFrame"] {border:1px solid #dee2e6;border-radius:6px;overflow:hidden;}
    [data-testid="stVegaLiteChart"] {border-radius:6px;background:#fff;padding:0;min-width:0;}
    .portal-heading {background:#002e40;color:white;border-radius:6px;padding:18px 22px;display:flex;justify-content:space-between;gap:16px;align-items:center;}
    .portal-heading .eyebrow {font-size:10px;letter-spacing:1.8px;color:#98d6e2;margin-bottom:7px;font-weight:600;}
    .portal-heading .title {font-size:23px;font-weight:600;letter-spacing:-.4px;}
    .portal-heading .version {font-size:11px;background:#124e63;border:1px solid #3a7385;padding:6px 10px;border-radius:4px;white-space:nowrap;}
    .portal-path {display:flex;gap:0;margin:2px 0 8px;color:#476471;background:#f7fafb;border:1px solid #dbe3e7;border-radius:6px;}
    .portal-path div {flex:1;padding:11px 16px;font-size:12px;border-right:1px solid #dbe3e7;}
    .portal-path div:last-child {border:0;}
    .portal-path b {color:#007a96;margin-right:8px;}
    @media(max-width:850px) {[data-testid="stMainBlockContainer"] {padding:4.5rem .7rem 1rem;} [data-baseweb="tab-panel"] {padding:12px;} [data-baseweb="tab"] {padding:0 10px;} .portal-path {flex-wrap:wrap;} .portal-path div {min-width:150px;} .portal-heading .title {font-size:19px;} [data-testid="stMain"] [data-testid="stMetricValue"] p {font-size:1.6rem!important;}}
    </style>''')


def header():
    st.html('''<div class="portal-heading"><div><div class="eyebrow">APPLICATION CONTROL / CLEANUP WORKSPACE</div><div class="title">Application hash health</div></div><span class="version">RC2 · Portal style</span></div>
    <div class="portal-path"><div><b>01</b> Discover applications</div><div><b>02</b> Review cleanup plans</div><div><b>03</b> Verify cleanup results</div></div>''')


def application_chart(rows,series):
    """Readable short labels, full application identity in hover details."""
    values=[]
    for row in rows:
        name=row['Application'];aid=row['Application ID']
        label=(name if len(name)<=30 else '…'+name[-27:])+' · '+aid[:8]
        for field,color in series:
            values.append({'Application':name,'Application ID':aid,'Label':label,'Stage':field,'Records':row[field]})
    st.vega_lite_chart(spec={'data':{'values':values},'height':max(150,min(470,len(rows)*36)),
        'mark':{'type':'bar','cornerRadiusEnd':3,'height':20},
        'encoding':{'y':{'field':'Label','type':'nominal','sort':'-x','axis':{'title':None,'labelLimit':270,'labelColor':'#405b68'}},
            'x':{'field':'Records','type':'quantitative','axis':{'title':'Records','tickMinStep':1,'gridColor':'#e9eef1','labelColor':'#627581'}},
            'color':{'field':'Stage','type':'nominal','scale':{'domain':[s[0] for s in series],'range':[s[1] for s in series]},'legend':{'title':None,'orient':'bottom'}},
            'tooltip':[{'field':'Application'},{'field':'Application ID'},{'field':'Stage'},{'field':'Records','format':','}]},
        'config':{'font':'Arial','view':{'stroke':None},'axis':{'domain':False,'tickSize':0,'labelPadding':8}}},width='stretch')
