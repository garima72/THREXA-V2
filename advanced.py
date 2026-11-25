"""THREXA 3.0 local-first investigation modules. Demo actions are simulations only."""
from flask import Blueprint, jsonify, request, Response
from pathlib import Path
from datetime import datetime, timezone
import sqlite3, json, csv, io, uuid, re, hashlib, secrets
from functools import wraps
from flask import session
import networkx as nx

bp = Blueprint('advanced', __name__)
BASE = Path(__file__).resolve().parent
DB = BASE / 'data' / 'threxa.db'
SEVERITY = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,entities TEXT NOT NULL,description TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '[]');
        CREATE TABLE IF NOT EXISTS ingested_events(id TEXT PRIMARY KEY,time TEXT,severity TEXT,title TEXT,description TEXT,entities TEXT,source TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS iocs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,value TEXT NOT NULL,threat TEXT NOT NULL,confidence INTEGER NOT NULL,source TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(kind,value));
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,salt TEXT NOT NULL,role TEXT NOT NULL,created_at TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS shadow_scenarios(id TEXT PRIMARY KEY,name TEXT NOT NULL,source_node TEXT NOT NULL,blocked_nodes TEXT NOT NULL,created_at TEXT NOT NULL,created_by TEXT NOT NULL,snapshot TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(id TEXT PRIMARY KEY,username TEXT NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL,created_at TEXT NOT NULL);
        ''')


def stamp(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def clean_text(x, n=500): return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(x or '')).strip()[:n]
def graph_data(): return json.loads((BASE/'data'/'graph.json').read_text(encoding='utf-8'))
def node_map(): return {n['id']: n for n in graph_data()['nodes']}
def event_entities(value):
    if isinstance(value, list): return [clean_text(x,80) for x in value[:30] if clean_text(x,80)]
    if isinstance(value, str): return [x.strip() for x in value.split(',') if x.strip()][:30]
    return []
def normalise_event(row, source='upload'):
    severity=clean_text(row.get('severity','medium'),20).lower()
    if severity not in SEVERITY: severity='medium'
    return {'id': clean_text(row.get('id') or 'EV-'+uuid.uuid4().hex[:8].upper(),80), 'time':clean_text(row.get('time') or row.get('timestamp') or stamp(),80), 'severity':severity, 'title':clean_text(row.get('title') or row.get('event') or 'Imported security event',180), 'description':clean_text(row.get('description') or row.get('message') or 'No description supplied.',1000), 'entities':event_entities(row.get('entities') or row.get('entity_ids')), 'source':source}


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 240000).hex()

def audit(action, detail=''):
    with db() as con:
        con.execute('INSERT INTO audit_log VALUES(?,?,?,?,?)',
          ('AUD-'+uuid.uuid4().hex[:10], session.get('user','system'), action, clean_text(detail,500), stamp()))

@bp.post('/api/auth/bootstrap')
def auth_bootstrap():
    init_db(); b=request.get_json(silent=True) or {}
    username=clean_text(b.get('username'),60); password=str(b.get('password') or '')
    if len(username)<3 or len(password)<12:
        return jsonify(error='Create an admin username (3+ chars) and password (12+ chars).'),400
    with db() as con:
        if con.execute('SELECT 1 FROM users').fetchone(): return jsonify(error='Initial admin already exists. Sign in instead.'),409
        salt=secrets.token_hex(16)
        con.execute('INSERT INTO users VALUES(?,?,?,?,?,?,1)',('USR-'+uuid.uuid4().hex[:10],username,password_hash(password,salt),salt,'Admin',stamp()))
    session['user']=username; session['role']='Admin'; audit('bootstrap_admin')
    return jsonify(ok=True,user=username,role='Admin')

@bp.post('/api/auth/login')
def auth_login():
    init_db(); b=request.get_json(silent=True) or {}; username=clean_text(b.get('username'),60); password=str(b.get('password') or '')
    with db() as con: r=con.execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone()
    if not r or not secrets.compare_digest(password_hash(password,r['salt']),r['password_hash']):
        return jsonify(error='Invalid username or password.'),401
    session.clear(); session['user']=username; session['role']=r['role']; audit('login')
    return jsonify(ok=True,user=username,role=r['role'])

@bp.post('/api/auth/logout')
def auth_logout():
    if session.get('user'): audit('logout')
    session.clear(); return jsonify(ok=True)

@bp.post('/api/auth/users')
def auth_create_user():
    if session.get('role')!='Admin': return jsonify(error='Only Admin can create users.'),403
    b=request.get_json(silent=True) or {}; username=clean_text(b.get('username'),60); password=str(b.get('password') or ''); role=b.get('role','Analyst')
    if len(username)<3 or len(password)<12 or role not in ('Admin','Analyst','SOC Manager','Viewer'):
        return jsonify(error='Username 3+ chars, password 12+ chars, and valid role required.'),400
    salt=secrets.token_hex(16)
    try:
        with db() as con: con.execute('INSERT INTO users VALUES(?,?,?,?,?,?,1)',('USR-'+uuid.uuid4().hex[:10],username,password_hash(password,salt),salt,role,stamp()))
    except sqlite3.IntegrityError: return jsonify(error='Username already exists.'),409
    audit('create_user',username+':'+role); return jsonify(ok=True),201

@bp.get('/api/auth/users')
def auth_users():
    if session.get('role')!='Admin': return jsonify(error='Only Admin can list users.'),403
    with db() as con: rows=con.execute('SELECT id,username,role,created_at,active FROM users ORDER BY created_at').fetchall()
    return jsonify(users=[dict(r) for r in rows])

@bp.get('/api/audit')
def audit_events():
    if session.get('role') not in ('Admin','SOC Manager'): return jsonify(error='Insufficient permissions.'),403
    with db() as con: rows=con.execute('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200').fetchall()
    return jsonify(events=[dict(r) for r in rows])

@bp.post('/api/shadow/scenarios')
def shadow_create():
    init_db(); b=request.get_json(silent=True) or {}; source=b.get('source_node'); blocked=b.get('blocked_nodes') or []
    nodes=node_map()
    if source not in nodes or not isinstance(blocked,list) or any(x not in nodes for x in blocked):
        return jsonify(error='Select a valid source and valid blocked asset IDs.'),400
    data=graph_data(); g=nx.Graph(); g.add_nodes_from(nodes)
    g.add_edges_from((e['source'],e['target']) for e in data['edges'] if e['source'] not in blocked and e['target'] not in blocked)
    # Snapshot is isolated: original graph JSON/Neo4j is never modified.
    reachable=nx.single_source_shortest_path_length(g,source,cutoff=5) if source not in blocked else {}
    impacted=[{'id':nid,'label':nodes[nid]['label'],'hops':hops,'criticality':nodes[nid].get('criticality','medium')} for nid,hops in reachable.items() if nid!=source]
    snap={'nodes':[{'id':n,'label':nodes[n]['label'],'blocked':n in blocked,'reachable':n in reachable} for n in nodes],
          'impacted':impacted,'blocked_nodes':blocked,'counts':{'reachable_assets':len(impacted),'blocked_assets':len(blocked),'critical_reachable':sum(x['criticality']=='critical' for x in impacted)}}
    sid='SHD-'+uuid.uuid4().hex[:10].upper(); name=clean_text(b.get('name') or 'Untitled scenario',100)
    with db() as con: con.execute('INSERT INTO shadow_scenarios VALUES(?,?,?,?,?,?,?)',(sid,name,source,json.dumps(blocked),stamp(),session.get('user','demo'),json.dumps(snap)))
    audit('shadow_scenario_created',sid)
    return jsonify(id=sid,name=name,source_node=source,created_at=stamp(),snapshot=snap,disclaimer='Isolated hypothetical graph snapshot; no production asset or source graph was changed.'),201

@bp.get('/api/shadow/scenarios')
def shadow_list():
    init_db()
    with db() as con: rows=con.execute('SELECT id,name,source_node,blocked_nodes,created_at,created_by FROM shadow_scenarios ORDER BY created_at DESC').fetchall()
    return jsonify(scenarios=[{**dict(r),'blocked_nodes':json.loads(r['blocked_nodes'])} for r in rows])

@bp.get('/api/shadow/scenarios/<sid>')
def shadow_detail(sid):
    init_db()
    with db() as con: r=con.execute('SELECT * FROM shadow_scenarios WHERE id=?',(sid,)).fetchone()
    if not r: return jsonify(error='Scenario not found.'),404
    d=dict(r); d['blocked_nodes']=json.loads(d['blocked_nodes']); d['snapshot']=json.loads(d['snapshot'])
    return jsonify(d,disclaimer='Stored scenario snapshot only; original graph remains unchanged.')

@bp.delete('/api/shadow/scenarios/<sid>')
def shadow_delete(sid):
    init_db()
    with db() as con: cur=con.execute('DELETE FROM shadow_scenarios WHERE id=?',(sid,))
    if not cur.rowcount: return jsonify(error='Scenario not found.'),404
    audit('shadow_scenario_deleted',sid); return jsonify(ok=True)


@bp.get('/api/health')
def health():
    init_db()
    with db() as con:
        counts={t:con.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('incidents','ingested_events','iocs')}
    return jsonify({'ok':True,'version':'3.0','storage':'SQLite local','counts':counts})

@bp.post('/api/logs/ingest')
def ingest_logs():
    init_db(); rows=[]; source='upload'
    if request.files:
        f=next(iter(request.files.values()))
        if len(f.read()) > 2_000_000: return jsonify(error='File exceeds 2 MB limit.'),413
        f.stream.seek(0); raw=f.read().decode('utf-8-sig',errors='replace')
        if f.filename.lower().endswith('.csv'):
            rows=list(csv.DictReader(io.StringIO(raw)))
        elif f.filename.lower().endswith('.json'):
            obj=json.loads(raw); rows=obj if isinstance(obj,list) else obj.get('events',[])
        else: return jsonify(error='Upload a .csv or .json file.'),400
        source=clean_text(f.filename,120)
    else:
        body=request.get_json(silent=True) or {}; rows=body.get('events',[])
    if not isinstance(rows,list) or not rows: return jsonify(error='No events found. Provide a JSON events array or CSV rows.'),400
    if len(rows)>5000: return jsonify(error='Maximum 5,000 events per import.'),400
    nodes=node_map(); accepted=[]; rejected=0
    for row in rows:
        if not isinstance(row,dict): rejected+=1; continue
        e=normalise_event(row,source)
        e['entities']=[x for x in e['entities'] if x in nodes]
        if not e['entities']: rejected+=1; continue
        accepted.append(e)
    with db() as con:
        for e in accepted:
            con.execute('INSERT OR REPLACE INTO ingested_events VALUES(?,?,?,?,?,?,?,?)',(e['id'],e['time'],e['severity'],e['title'],e['description'],json.dumps(e['entities']),e['source'],stamp()))
    return jsonify({'ok':True,'accepted':len(accepted),'rejected':rejected,'source':source,'message':'Imported events are stored locally and labelled as uploaded evidence.'})

@bp.get('/api/logs')
def list_logs():
    init_db()
    with db() as con: rows=con.execute('SELECT * FROM ingested_events ORDER BY created_at DESC LIMIT 300').fetchall()
    return jsonify(events=[{**dict(r),'entities':json.loads(r['entities'])} for r in rows])

@bp.route('/api/incidents',methods=['GET','POST'])
def incidents():
    init_db()
    if request.method=='POST':
        b=request.get_json(silent=True) or {}; title=clean_text(b.get('title'),180); entities=event_entities(b.get('entities')); nodes=node_map()
        if not title or not entities: return jsonify(error='Title and at least one valid graph entity are required.'),400
        entities=[x for x in entities if x in nodes]
        if not entities: return jsonify(error='No valid graph entity IDs supplied.'),400
        sev=clean_text(b.get('severity','high'),20).lower(); sev=sev if sev in SEVERITY else 'medium'; now=stamp(); iid='INC-'+uuid.uuid4().hex[:8].upper()
        with db() as con: con.execute('INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?)',(iid,title,sev,'New',json.dumps(entities),clean_text(b.get('description'),1000),now,now,'[]'))
        return jsonify({'ok':True,'incident':incident_by_id(iid)}),201
    with db() as con: rows=con.execute('SELECT * FROM incidents ORDER BY created_at DESC').fetchall()
    return jsonify(incidents=[incident_row(r) for r in rows])

def incident_row(r):
    d=dict(r); d['entities']=json.loads(d['entities']); d['notes']=json.loads(d['notes']); return d
def incident_by_id(iid):
    with db() as con: r=con.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
    return incident_row(r) if r else None

@bp.patch('/api/incidents/<iid>')
def update_incident(iid):
    init_db(); b=request.get_json(silent=True) or {}; allowed={'New','Investigating','Contained','Resolved'}; status=b.get('status')
    with db() as con:
        r=con.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
        if not r: return jsonify(error='Incident not found.'),404
        notes=json.loads(r['notes'])
        if b.get('note'):
            note=clean_text(b['note'],1000)
            if note: notes.append({'time':stamp(),'text':note})
        if status and status not in allowed: return jsonify(error='Invalid status.'),400
        con.execute('UPDATE incidents SET status=?,notes=?,updated_at=? WHERE id=?',(status or r['status'],json.dumps(notes),stamp(),iid))
    return jsonify(incident=incident_by_id(iid))

@bp.get('/api/risk')
def risk_scores():
    data=graph_data(); nodes={n['id']:n for n in data['nodes']}; g=nx.Graph(); g.add_nodes_from(nodes); g.add_edges_from((e['source'],e['target']) for e in data['edges'])
    central=nx.betweenness_centrality(g); maxc=max(central.values(),default=0) or 1
    with db() as con: ev=con.execute('SELECT severity,entities FROM ingested_events').fetchall()
    counts={k:0 for k in nodes}; sevcount={k:0 for k in nodes}
    for r in ev:
        for k in json.loads(r['entities']):
            if k in counts: counts[k]+=1; sevcount[k]=max(sevcount[k],SEVERITY.get(r['severity'],0))
    output=[]
    for k,n in nodes.items():
        crit={'low':20,'medium':45,'high':70,'critical':90}.get(n.get('criticality'),45)
        activity=min(100,counts[k]*18); structural=round(central.get(k,0)/maxc*100)
        score=round(.45*crit+.35*activity+.20*structural)
        output.append({'id':k,'label':n['label'],'criticality':n.get('criticality'),'score':score,'event_count':counts[k],'factors':{'asset_criticality':crit,'uploaded_event_activity':activity,'graph_centrality':structural},'basis':'Transparent heuristic; not a probability of compromise.'})
    return jsonify(items=sorted(output,key=lambda x:x['score'],reverse=True))

@bp.post('/api/simulate')
def simulate():
    b=request.get_json(silent=True) or {}; source=b.get('node_id'); nodes=node_map(); data=graph_data()
    if source not in nodes: return jsonify(error='Choose a valid asset.'),400
    g=nx.Graph(); g.add_nodes_from(nodes); g.add_edges_from((e['source'],e['target']) for e in data['edges'])
    dist=nx.single_source_shortest_path_length(g,source,cutoff=4); impacted=[]
    for nid,hops in dist.items():
        if nid==source: continue
        n=nodes[nid]; impacted.append({'id':nid,'label':n['label'],'type':n['type'],'criticality':n['criticality'],'hops':hops,'business_impact':n['type']=='business_service'})
    impacted.sort(key=lambda x:(not x['business_impact'],x['hops'], -{'low':1,'medium':2,'high':3,'critical':4}.get(x['criticality'],2)))
    services=[x for x in impacted if x['business_impact']]
    return jsonify({'scenario':f'Hypothetical compromise of {nodes[source]["label"]}','source':nodes[source],'impacted':impacted,'business_services_at_risk':services,'counts':{'assets':len(impacted),'business_services':len(services),'critical_assets':sum(x['criticality']=='critical' for x in impacted)},'disclaimer':'What-if graph reachability only. No host, account, firewall, or production system was changed.'})

@bp.get('/api/playbooks/<severity>')
def playbooks(severity):
    severity=severity.lower()
    actions=[{'step':1,'action':'Preserve evidence','detail':'Record alert IDs, timestamps, affected entities, and relevant logs before making changes.','approval':'Analyst review'},{'step':2,'action':'Validate scope','detail':'Confirm the affected identity, host, connections, and business owner.','approval':'Analyst review'},{'step':3,'action':'Contain with approval','detail':'Prepare host isolation or account disablement only after impact review and authorization.','approval':'Human approval required'},{'step':4,'action':'Recover and monitor','detail':'Apply remediation, rotate exposed credentials where appropriate, and monitor for recurrence.','approval':'Change approval'}]
    if severity not in SEVERITY: return jsonify(error='Unknown severity.'),404
    return jsonify({'severity':severity,'playbook':actions,'execution':'recommendation_only','note':'No response action is executed by this demo.'})

@bp.post('/api/copilot/chat')
def copilot_chat():
    b=request.get_json(silent=True) or {}; q=clean_text(b.get('question'),500).lower()
    if not q: return jsonify(error='Enter a question.'),400
    data=graph_data(); nodes={n['id']:n for n in data['nodes']}
    with db() as con: ev=con.execute('SELECT * FROM ingested_events ORDER BY created_at DESC LIMIT 100').fetchall()
    if any(w in q for w in ('risk','score','highest')):
        return jsonify({'answer':'Risk scores combine asset criticality (45%), uploaded-event activity (35%), and graph centrality (20%). They are prioritization heuristics, not probabilities. Open Risk Assessment to inspect per-asset factors.','evidence':['Graph asset criticality labels','Uploaded event references','NetworkX betweenness centrality'],'mode':'local explainable rules'})
    if any(w in q for w in ('path','attack','reach')):
        return jsonify({'answer':'Use Attack Path Analysis to choose a source and target. The current graph is a relationship model; a graph path indicates modeled connectivity, not proof of exploitation or attacker movement.','evidence':[f'{len(data["nodes"])} modeled assets',f'{len(data["edges"])} modeled relationships'],'mode':'local explainable rules'})
    if any(w in q for w in ('incident','alert','event')):
        sev={s:0 for s in SEVERITY}
        for e in ev: sev[e['severity']]=sev.get(e['severity'],0)+1
        return jsonify({'answer':f'There are {len(ev)} uploaded events currently stored. Severity breakdown: '+', '.join(f'{k}: {v}' for k,v in sev.items())+'. Create an incident from the Incident Center after validating affected entities.','evidence':[f'{len(ev)} locally stored uploaded events'],'mode':'local explainable rules'})
    return jsonify({'answer':'I can explain risk scoring, modeled attack paths, uploaded events, and investigation workflow. Ask a focused question such as “Why is this asset high risk?” or “How should I investigate this alert?”. This local demo copilot uses transparent rules; it is not an external generative-AI service.','evidence':['THREXA graph and locally ingested events'],'mode':'local explainable rules'})

@bp.get('/api/report')
def report():
    init_db()
    with db() as con:
        inc=[incident_row(r) for r in con.execute('SELECT * FROM incidents ORDER BY created_at DESC').fetchall()]
        events=con.execute('SELECT COUNT(*) FROM ingested_events').fetchone()[0]
        iocs=con.execute('SELECT COUNT(*) FROM iocs').fetchone()[0]
    payload={'product':'THREXA 3.0','generated_at':stamp(),'dataset_notice':'The bundled environment and alerts are synthetic demonstration data. Uploaded events are separately stored and labelled.','summary':{'incidents':len(inc),'uploaded_events':events,'iocs':iocs},'incidents':inc,'limitations':['Risk score is a transparent heuristic, not compromise probability.','Graph reachability is not proof of exploitability.','Response playbooks are recommendations; no production actions are executed.']}
    return Response(json.dumps(payload,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename=threxa-investigation-report.json'})

init_db()

@bp.route('/api/iocs',methods=['GET','POST'])
def iocs():
    init_db()
    if request.method=='POST':
        b=request.get_json(silent=True) or {}; kind=clean_text(b.get('kind'),30).lower(); value=clean_text(b.get('value'),255); threat=clean_text(b.get('threat') or 'suspicious',80); source=clean_text(b.get('source') or 'analyst-entered',120)
        if kind not in ('ip','domain','hash','url') or not value: return jsonify(error='IOC kind must be ip, domain, hash, or url; value is required.'),400
        try:
            with db() as con: con.execute('INSERT INTO iocs VALUES(?,?,?,?,?,?,?)',('IOC-'+uuid.uuid4().hex[:8].upper(),kind,value,threat,max(0,min(100,int(b.get('confidence',50)))),source,stamp()))
        except sqlite3.IntegrityError: return jsonify(error='This IOC already exists.'),409
        return jsonify(ok=True,message='IOC stored locally. No external reputation lookup was performed.'),201
    with db() as con: rows=con.execute('SELECT * FROM iocs ORDER BY created_at DESC').fetchall()
    return jsonify(iocs=[dict(r) for r in rows])

@bp.get('/api/timeline')
def timeline():
    init_db(); events=[]
    # The bundled alert feed is synthetic; uploaded records are marked distinctly.
    try:
        sample=json.loads((BASE/'data'/'alerts.json').read_text(encoding='utf-8'))
        events.extend([{**e,'origin':'bundled synthetic alert'} for e in sample])
    except Exception: pass
    with db() as con: rows=con.execute('SELECT * FROM ingested_events').fetchall()
    events.extend([{**dict(r),'entities':json.loads(r['entities']),'origin':'uploaded evidence'} for r in rows])
    events.sort(key=lambda x:str(x.get('time','')),reverse=True)
    return jsonify(events=events[:300],notice='Bundled alerts are synthetic. Uploaded events are user-provided imports.')
