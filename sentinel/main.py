import asyncio
import hashlib
import json
import logging
from pathlib import Path
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from .db import Base, engine, get_db, SessionLocal
from .models import (
    ApprovalRecord,
    AuditLog,
    DetectionFinding,
    DetectionRule,
    Incident,
    IncidentEvent,
    Investigation,
    ModelMetadata,
    ReplayScenario,
    ReplaySession,
    ResponseAction,
    SecurityEvent,
    now,
)
from .schemas import EventIn, IncidentPatch, ReplayIn
from .detection import process_event, seed_rules
from .generator import generate
from .config import CORS_ORIGINS, DEMO_TOKEN, REPLAY_DELAY
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('sentinel')
EVENTS_ACCEPTED = Counter('sentinel_events_accepted_total', 'Accepted synthetic security events')
EVENTS_DUPLICATE = Counter('sentinel_events_duplicate_total', 'Duplicate event IDs')
FINDINGS = Counter('sentinel_findings_total', 'Detection findings created', ['rule'])
app = FastAPI(title='Sentinel AI', version='1.0.0', description='Synthetic telemetry security operations demonstration')
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=False, allow_methods=['GET', 'POST', 'PATCH', 'OPTIONS'], allow_headers=['*'])

# Initialize persistence and seed built-in records before serving requests.
@app.on_event('startup')
def startup():
    """Create the local schema and idempotently register built-in rules/scenarios."""
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_rules(db)
        if not db.get(ModelMetadata, 'iforest-synthetic-v1'):
            db.add(ModelMetadata(model_id='iforest-synthetic-v1', algorithm='IsolationForest (optional)', version='1.0', feature_schema='["hour_utc","source_frequency","category_code","outcome_code"]', threshold=0.72, trained_at=None, status='cold_start'))
        defaults = [('credential-chain', 'Credential guessing and follow-up', 'Synthetic repeated login failures followed by success.', 180, ['AUTH-FAIL-BURST', 'AUTH-FAIL-SUCCESS'], 42), ('multi-stage-lab', 'Multi-stage synthetic activity', 'Process and privilege signals across a lab network.', 220, ['PROCESS-UNUSUAL', 'PRIV-CHANGE'], 77)]
        for sid, name, desc, count, expected, seed in defaults:
            if not db.get(ReplayScenario, sid):
                db.add(ReplayScenario(scenario_id=sid, name=name, description=desc, event_count=count, expected_rules=json.dumps(expected), seed=seed))
        db.commit()

def event_dict(e):
    return {c.name: as_utc(getattr(e, c.name)).isoformat() if isinstance(getattr(e, c.name), datetime) else getattr(e, c.name) for c in SecurityEvent.__table__.columns}

def as_utc(value):
    """SQLite may return naive datetimes; persisted event times are defined as UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def expired(value):
    return as_utc(value) < now()

def finding_dict(f):
    return {'finding_id': f.finding_id, 'rule_id': f.rule_id, 'title': f.title, 'severity': f.severity, 'confidence': f.confidence, 'explanation': f.explanation, 'evidence_ids': json.loads(f.evidence_ids), 'technique_id': f.technique_id, 'technique_name': f.technique_name, 'created_at': as_utc(f.created_at).isoformat(), 'incident_id': f.incident_id}

def incident_dict(i):
    return {'incident_id': i.incident_id, 'title': i.title, 'severity': i.severity, 'status': i.status, 'assignee': i.assignee, 'summary': i.summary, 'created_at': as_utc(i.created_at).isoformat(), 'updated_at': as_utc(i.updated_at).isoformat()}

def rowdict(r):
    return {c.name: as_utc(getattr(r, c.name)).isoformat() if isinstance(getattr(r, c.name), datetime) else getattr(r, c.name) for c in r.__table__.columns}

def analyst(authorization: str | None=Header(default=None, alias='X-Analyst-Token'), role: str=Header(default='viewer', alias='X-Analyst-Role'), name: str=Header(default='demo-analyst', alias='X-Analyst-Name')):
    """Resolve the explicitly limited local-demo identity from request headers."""
    if authorization != DEMO_TOKEN:
        raise HTTPException(401, detail={'code': 'unauthorized', 'message': 'A valid demo analyst token is required.'})
    return {'name': name[:128], 'role': role}

def require_admin(user=Depends(analyst)):
    if user['role'] != 'admin':
        raise HTTPException(403, detail={'code': 'forbidden', 'message': 'Admin role required.'})
    return user

def ingest(db: Session, payload: EventIn, replay_id=None):
    """Persist an idempotent event and its detection results in one transaction."""
    if db.get(SecurityEvent, payload.event_id):
        EVENTS_DUPLICATE.inc()
        return (False, [])
    # Keep JSON payloads separate from normalized columns and bound their size in EventIn.
    data = payload.model_dump()
    data['observed_at'] = data['observed_at'] or now()
    data['raw_event'] = json.dumps(data['raw_event'], ensure_ascii=False)
    data['normalized_attributes'] = json.dumps(data['normalized_attributes'], ensure_ascii=False)
    data['replay_id'] = replay_id
    e = SecurityEvent(**data)
    db.add(e)
    db.flush()
    found = process_event(db, e)
    for f in found:
        FINDINGS.labels(f.rule_id).inc()
        if f.incident_id and (not db.scalar(select(ResponseAction).where(ResponseAction.incident_id == f.incident_id, ResponseAction.action_type == 'open_investigation'))):
            target = f.incident_id
            payload_hash = hashlib.sha256(json.dumps({'action_type': 'open_investigation', 'target': target, 'incident_id': f.incident_id}, sort_keys=True).encode()).hexdigest()
            db.add(ResponseAction(action_id=str(uuid4()), incident_id=f.incident_id, action_type='open_investigation', target=target, rationale=f'Detection {f.rule_id} requests analyst follow-up.', expected_impact='Creates a simulated investigation task only.', risk='low', payload_hash=payload_hash, state='pending', expires_at=now() + timedelta(minutes=15)))
    db.commit()
    EVENTS_ACCEPTED.inc()
    logger.info(json.dumps({'message': 'event_ingested', 'event_id': e.event_id, 'correlation_id': payload.correlation_id, 'findings': len(found)}))
    return (True, found)

# Liveness stays outside the versioned business API for container health checks.
@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'sentinel-api'}

@app.get('/ready')
def ready():
    try:
        with engine.connect() as c:
            c.exec_driver_sql('SELECT 1')
        return {'status': 'ready', 'database': 'ok'}
    except Exception:
        raise HTTPException(503, detail={'code': 'not_ready', 'message': 'Database unavailable'})

@app.get('/metrics')
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Telemetry APIs use bounded pages and stable event IDs for idempotent ingestion.
@app.post('/api/v1/events', status_code=202)
def create_event(payload: EventIn, db: Session=Depends(get_db), user=Depends(analyst)):
    ok, findings = ingest(db, payload)
    return {'accepted': ok, 'duplicate': not ok, 'event_id': payload.event_id, 'findings_created': [finding_dict(f) for f in findings]}

@app.post('/api/v1/events/bulk', status_code=202)
def bulk_events(events: list[EventIn], db: Session=Depends(get_db), user=Depends(analyst)):
    if not 1 <= len(events) <= 500:
        raise HTTPException(422, detail={'code': 'invalid_batch', 'message': 'Batch size must be between 1 and 500.'})
    accepted = duplicates = 0
    for e in events:
        ok, _ = ingest(db, e)
        accepted += ok
        duplicates += not ok
    return {'accepted': accepted, 'duplicates': duplicates, 'submitted': len(events)}

@app.get('/api/v1/events')
def list_events(search: str | None=None, severity: str | None=None, category: str | None=None, source: str | None=None, host: str | None=None, user_name: str | None=Query(default=None, alias='user'), scenario_id: str | None=None, limit: int=Query(50, ge=1, le=200), offset: int=Query(0, ge=0), db: Session=Depends(get_db)):
    q = select(SecurityEvent)
    if severity:
        q = q.where(SecurityEvent.severity == severity)
    if category:
        q = q.where(SecurityEvent.event_category == category)
    if source:
        q = q.where(SecurityEvent.source_ip == source)
    if host:
        q = q.where(SecurityEvent.hostname == host)
    if user_name:
        q = q.where(SecurityEvent.username == user_name)
    if scenario_id:
        q = q.where(SecurityEvent.scenario_id == scenario_id)
    if search:
        q = q.where(SecurityEvent.event_action.contains(search[:100]) | SecurityEvent.username.contains(search[:100]) | SecurityEvent.hostname.contains(search[:100]))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = list(db.scalars(q.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit)))
    return {'items': [event_dict(e) for e in rows], 'total': total, 'limit': limit, 'offset': offset}

@app.get('/api/v1/events/{event_id}')
def get_event(event_id: str, db: Session=Depends(get_db)):
    e = db.get(SecurityEvent, event_id)
    if not e:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Event not found'})
    return event_dict(e)

@app.get('/api/v1/findings')
def list_findings(limit: int=Query(50, ge=1, le=200), offset: int=Query(0, ge=0), db: Session=Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(DetectionFinding))
    rows = list(db.scalars(select(DetectionFinding).order_by(desc(DetectionFinding.created_at)).offset(offset).limit(limit)))
    return {'items': [finding_dict(x) for x in rows], 'total': total, 'limit': limit, 'offset': offset}

# Incident changes and investigation summaries preserve an auditable evidence trail.
@app.get('/api/v1/incidents')
def incidents(status: str | None=None, severity: str | None=None, limit: int=Query(50, ge=1, le=200), offset: int=Query(0, ge=0), db: Session=Depends(get_db)):
    q = select(Incident)
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = list(db.scalars(q.order_by(desc(Incident.updated_at)).offset(offset).limit(limit)))
    return {'items': [incident_dict(x) for x in rows], 'total': total, 'limit': limit, 'offset': offset}

@app.get('/api/v1/incidents/{incident_id}')
def incident_detail(incident_id: str, db: Session=Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Incident not found'})
    events = list(db.scalars(select(SecurityEvent).join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.event_id).where(IncidentEvent.incident_id == incident_id).order_by(SecurityEvent.timestamp).limit(500)))
    findings = list(db.scalars(select(DetectionFinding).where(DetectionFinding.incident_id == incident_id)))
    actions = list(db.scalars(select(ResponseAction).where(ResponseAction.incident_id == incident_id)))
    return {**incident_dict(i), 'events': [event_dict(e) for e in events], 'findings': [finding_dict(f) for f in findings], 'actions': [rowdict(a) for a in actions]}

@app.patch('/api/v1/incidents/{incident_id}')
def patch_incident(incident_id: str, payload: IncidentPatch, db: Session=Depends(get_db), user=Depends(analyst)):
    i = db.get(Incident, incident_id)
    if not i:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Incident not found'})
    changes = payload.model_dump(exclude_none=True)
    comment = changes.pop('comment', None)
    for k, v in changes.items():
        setattr(i, k, v)
    i.updated_at = now()
    if comment:
        db.add(AuditLog(audit_id=str(uuid4()), actor=user['name'], action='incident.comment', object_type='incident', object_id=incident_id, details=comment))
    db.add(AuditLog(audit_id=str(uuid4()), actor=user['name'], action='incident.updated', object_type='incident', object_id=incident_id, details=json.dumps(changes)))
    db.commit()
    return incident_dict(i)

@app.get('/api/v1/incidents/{incident_id}/timeline')
def timeline(incident_id: str, db: Session=Depends(get_db)):
    if not db.get(Incident, incident_id):
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Incident not found'})
    evs = list(db.scalars(select(SecurityEvent).join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.event_id).where(IncidentEvent.incident_id == incident_id).order_by(SecurityEvent.timestamp).limit(500)))
    return {'items': [event_dict(e) for e in evs]}

@app.post('/api/v1/incidents/{incident_id}/investigate')
def investigate(incident_id: str, db: Session=Depends(get_db), user=Depends(analyst)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Incident not found'})
    events = list(db.scalars(select(SecurityEvent).join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.event_id).where(IncidentEvent.incident_id == incident_id).order_by(SecurityEvent.timestamp).limit(100)))
    evidence = {e.event_id: e for e in events}
    pkg = str(uuid4())
    facts = [{'claim': f'{e.event_action} event in category {e.event_category} was observed at {as_utc(e.timestamp).isoformat()}.', 'event_ids': [e.event_id]} for e in events[:20]]
    output = {'summary': inc.summary, 'provider': 'deterministic', 'evidence_package_id': pkg, 'observed_facts': facts, 'timeline': [{'event_id': e.event_id, 'timestamp': as_utc(e.timestamp).isoformat(), 'category': e.event_category, 'action': e.event_action} for e in events], 'entities': sorted({x for e in events for x in (e.username, e.hostname, e.source_ip) if x}), 'potential_explanations': ['The correlated events may represent suspicious activity requiring analyst review.'], 'benign_alternatives': ['Authorized testing, user error, or scheduled automation may explain some events.'], 'confidence_rationale': 'Confidence reflects rule thresholds and evidence count; it is not a probability of compromise.', 'mappings': [{'technique_id': f.technique_id, 'name': f.technique_name, 'rule_id': f.rule_id, 'event_ids': json.loads(f.evidence_ids)} for f in db.scalars(select(DetectionFinding).where(DetectionFinding.incident_id == incident_id)) if f.technique_id], 'next_steps': ['Confirm the activity with the account owner.', 'Review adjacent authentication and host telemetry.'], 'containment_recommendations': ['Consider a simulated response action after validating impact.'], 'unknowns': ['This local demo uses synthetic events and has no identity-provider context.']}
    allowed = set(evidence)
    for claim in output['observed_facts']:
        if not claim['event_ids'] or not set(claim['event_ids']).issubset(allowed):
            raise HTTPException(422, detail={'code': 'invalid_evidence_reference', 'message': 'Investigation cited unavailable evidence'})
    db.add(Investigation(investigation_id=str(uuid4()), incident_id=incident_id, provider='deterministic', prompt_version='fallback-v1', evidence_package_id=pkg, output=json.dumps(output)))
    db.add(AuditLog(audit_id=str(uuid4()), actor=user['name'], action='investigation.generated', object_type='incident', object_id=incident_id, details=pkg))
    db.commit()
    return output

# The graph is derived from stored event fields and always has a node limit.
@app.get('/api/v1/rules')
def rules(db: Session=Depends(get_db)):
    return {'items': [rowdict(x) for x in db.scalars(select(DetectionRule).order_by(DetectionRule.rule_id))], 'coverage_note': 'Technique mappings describe supported detection logic, not confirmed attacker behavior.', 'known_gaps': ['Unusual source IP baselining is not yet an active production detector.', 'Cross-host correlation is currently represented by incident/entity links, not a probabilistic causal model.']}

@app.get('/api/v1/models/status')
def model_status(db: Session=Depends(get_db)):
    m = db.get(ModelMetadata, 'iforest-synthetic-v1')
    return {**rowdict(m), 'score_kind': 'anomaly score, not probability of compromise', 'note': 'Cold start; deterministic rules remain active.'}

@app.get('/api/v1/entities/graph')
def graph(limit: int=Query(300, ge=1, le=500), db: Session=Depends(get_db)):
    events = list(db.scalars(select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)))
    nodes = {}
    edges = {}

    def node(kind, label):
        if not label:
            return None
        ident = f'{kind}:{label}'
        nodes[ident] = {'id': ident, 'type': kind, 'label': label}
        return ident
    for e in events:
        ids = [node('event', e.event_id), node('user', e.username), node('host', e.hostname), node('ip', e.source_ip), node('process', e.process_name)]
        for left, right, typ in ((ids[0], ids[1], 'observed_user'), (ids[0], ids[2], 'observed_on'), (ids[0], ids[3], 'source_ip'), (ids[0], ids[4], 'process')):
            if left and right:
                edges[left, right, typ] = {'source': left, 'target': right, 'type': typ, 'why': e.event_id, 'inferred': False}
        for f in db.scalars(select(DetectionFinding).where(DetectionFinding.evidence_ids.contains(e.event_id)).limit(10)):
            fi = node('finding', f.finding_id)
            if ids[0]:
                edges[fi, ids[0], 'supported_by'] = {'source': fi, 'target': ids[0], 'type': 'supported_by', 'why': f.rule_id, 'inferred': False}
    return {'nodes': list(nodes.values())[:limit], 'edges': list(edges.values())[:limit * 4], 'legend': {'observed': 'Directly stored event relation', 'inferred': 'Temporal/statistical association'}}

@app.get('/api/v1/scenarios')
def scenarios(db: Session=Depends(get_db)):
    return {'items': [rowdict(x) for x in db.scalars(select(ReplayScenario))]}

def run_replay(replay_id, scenario, speed):
    """Stream events through ingestion while honoring the replay session state."""
    try:
        # Session-specific IDs make repeated runs isolated while preserving scenario labels.
        generated = generate(scenario.event_count, scenario.seed, f'{scenario.scenario_id}:{replay_id}')
        generated = [event.model_copy(update={'scenario_id': scenario.scenario_id}) for event in generated]
        for n, p in enumerate(generated):
            with SessionLocal() as db:
                session = db.get(ReplaySession, replay_id)
                if not session or session.state in ('cancelled', 'failed'):
                    return
                while session.state == 'paused':
                    db.close()
                    time.sleep(0.25)
                    db = SessionLocal()
                    session = db.get(ReplaySession, replay_id)
                    if not session or session.state != 'paused':
                        break
                if session.state == 'cancelled':
                    return
                ingest(db, p, replay_id)
                session.progress = n + 1
                if n + 1 >= len(generated):
                    session.state = 'completed'
                db.commit()
            if REPLAY_DELAY:
                time.sleep(REPLAY_DELAY / max(speed, 0.1))
    except Exception as exc:
        with SessionLocal() as db:
            s = db.get(ReplaySession, replay_id)
            if s:
                s.state = 'failed'
                s.error = str(exc)[:500]
                db.commit()

# Replay workers stream events through the same ingestion path as live submissions.
@app.post('/api/v1/replays', status_code=202)
def start_replay(payload: ReplayIn, db: Session=Depends(get_db), user=Depends(analyst)):
    scenario = db.get(ReplayScenario, payload.scenario_id)
    if not scenario:
        raise HTTPException(404, detail={'code': 'scenario_not_found', 'message': 'Scenario not found'})
    rid = str(uuid4())
    s = ReplaySession(replay_id=rid, scenario_id=scenario.scenario_id, state='running', speed=payload.speed, progress=0, total=scenario.event_count)
    db.add(s)
    db.commit()
    threading.Thread(target=run_replay, args=(rid, scenario, payload.speed), daemon=True).start()
    return rowdict(s)

@app.get('/api/v1/replays/{replay_id}')
def replay_status(replay_id: str, db: Session=Depends(get_db)):
    s = db.get(ReplaySession, replay_id)
    if not s:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Replay not found'})
    return rowdict(s)

def replay_change(replay_id, state, db):
    s = db.get(ReplaySession, replay_id)
    if not s:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Replay not found'})
    valid = {'paused': {'running'}, 'running': {'paused'}, 'cancelled': {'running', 'paused'}}
    if s.state not in valid.get(state, set()):
        raise HTTPException(409, detail={'code': 'invalid_replay_transition', 'message': f'Cannot transition {s.state} to {state}'})
    s.state = state
    db.commit()
    return rowdict(s)

@app.post('/api/v1/replays/{replay_id}/pause')
def pause_replay(replay_id, db: Session=Depends(get_db), user=Depends(analyst)):
    return replay_change(replay_id, 'paused', db)

@app.post('/api/v1/replays/{replay_id}/resume')
def resume_replay(replay_id, db: Session=Depends(get_db), user=Depends(analyst)):
    return replay_change(replay_id, 'running', db)

@app.post('/api/v1/replays/{replay_id}/cancel')
def cancel_replay(replay_id, db: Session=Depends(get_db), user=Depends(analyst)):
    return replay_change(replay_id, 'cancelled', db)

@app.post('/api/v1/replays/{replay_id}/reset')
def reset_replay(replay_id, db: Session=Depends(get_db), user=Depends(analyst)):
    s = db.get(ReplaySession, replay_id)
    if not s:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Replay not found'})
    if s.state in ('running', 'paused'):
        raise HTTPException(409, detail={'code': 'replay_active', 'message': 'Cancel replay before reset'})
    replay_incidents = list(db.scalars(select(Incident).where(Incident.correlation_key.contains(f':replay:{replay_id}'))))
    incident_ids = [i.incident_id for i in replay_incidents]
    action_ids = list(db.scalars(select(ResponseAction.action_id).where(ResponseAction.incident_id.in_(incident_ids)))) if incident_ids else []
    if action_ids:
        db.query(ApprovalRecord).filter(ApprovalRecord.action_id.in_(action_ids)).delete(synchronize_session=False)
    if action_ids:
        db.query(ResponseAction).filter(ResponseAction.action_id.in_(action_ids)).delete(synchronize_session=False)
    if incident_ids:
        db.query(IncidentEvent).filter(IncidentEvent.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    for incident in replay_incidents:
        db.delete(incident)
    db.query(DetectionFinding).filter(DetectionFinding.replay_id == replay_id).delete()
    db.query(SecurityEvent).filter(SecurityEvent.replay_id == replay_id).delete()
    s.state = 'reset'
    s.progress = 0
    db.commit()
    return rowdict(s)

def make_action(db, incident, action_type, target, rationale, impact, risk='medium'):
    """Create a short-lived proposal bound to a canonical simulation payload."""
    payload = {'action_type': action_type, 'target': target, 'incident_id': incident.incident_id}
    ah = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    a = ResponseAction(action_id=str(uuid4()), incident_id=incident.incident_id, action_type=action_type, target=target, rationale=rationale, expected_impact=impact, risk=risk, payload_hash=ah, state='pending', expires_at=now() + timedelta(minutes=15))
    db.add(a)
    db.add(AuditLog(audit_id=str(uuid4()), actor='sentinel-policy', action='response.proposed', object_type='response_action', object_id=a.action_id, details=json.dumps(payload)))
    db.commit()
    return a

# Response adapters below only update Sentinel's simulation state.
@app.get('/api/v1/response-actions')
def response_actions(state: str | None=None, db: Session=Depends(get_db)):
    q = select(ResponseAction)
    if state:
        q = q.where(ResponseAction.state == state)
    return {'items': [rowdict(a) for a in db.scalars(q.order_by(desc(ResponseAction.created_at)).limit(200))]}

@app.post('/api/v1/incidents/{incident_id}/response-actions', status_code=201)
def propose_action(incident_id: str, action_type: str=Query(..., pattern='^(lock_synthetic_account|block_synthetic_ip|isolate_synthetic_host|open_investigation|raise_severity|add_note)$'), target: str=Query(..., min_length=1, max_length=180), db: Session=Depends(get_db), user=Depends(analyst)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Incident not found'})
    if action_type.startswith(('lock_', 'block_', 'isolate_')) and (not (target.endswith('.test') or target.startswith(('demo-', 'lab-', '192.0.2.', '198.51.100.', '203.0.113.')))):
        raise HTTPException(422, detail={'code': 'synthetic_target_required', 'message': 'Only synthetic targets may be used'})
    return rowdict(make_action(db, inc, action_type, target, 'Analyst-proposed simulation action for investigation.', 'Changes only Sentinel simulation state.'))

@app.post('/api/v1/response-actions/{action_id}/approve')
def approve_action(action_id: str, db: Session=Depends(get_db), user=Depends(require_admin)):
    a = db.get(ResponseAction, action_id)
    if not a:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Action not found'})
    if a.state != 'pending' or expired(a.expires_at):
        raise HTTPException(409, detail={'code': 'approval_invalid', 'message': 'Action is not pending or has expired'})
    a.state = 'approved'
    db.add(ApprovalRecord(approval_id=str(uuid4()), action_id=a.action_id, payload_hash=a.payload_hash, decision='approved', analyst=user['name']))
    db.add(AuditLog(audit_id=str(uuid4()), actor=user['name'], action='response.approved', object_type='response_action', object_id=a.action_id, details=a.payload_hash))
    db.commit()
    return rowdict(a)

@app.post('/api/v1/response-actions/{action_id}/reject')
def reject_action(action_id: str, db: Session=Depends(get_db), user=Depends(require_admin)):
    a = db.get(ResponseAction, action_id)
    if not a:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Action not found'})
    if a.state != 'pending':
        raise HTTPException(409, detail={'code': 'invalid_state', 'message': 'Only pending actions may be rejected'})
    a.state = 'rejected'
    db.add(ApprovalRecord(approval_id=str(uuid4()), action_id=a.action_id, payload_hash=a.payload_hash, decision='rejected', analyst=user['name']))
    db.add(AuditLog(audit_id=str(uuid4()), actor=user['name'], action='response.rejected', object_type='response_action', object_id=a.action_id, details=a.payload_hash))
    db.commit()
    return rowdict(a)

@app.post('/api/v1/response-actions/{action_id}/execute')
def execute_action(action_id: str, idempotency_key: str | None=Header(default=None, alias='Idempotency-Key'), db: Session=Depends(get_db), user=Depends(require_admin)):
    """Run allowlisted in-app adapters only after payload-bound approval."""
    a = db.get(ResponseAction, action_id)
    if not a:
        raise HTTPException(404, detail={'code': 'not_found', 'message': 'Action not found'})
    if a.state == 'succeeded':
        return rowdict(a)
    approval = db.scalar(select(ApprovalRecord).where(ApprovalRecord.action_id == a.action_id, ApprovalRecord.decision == 'approved').order_by(desc(ApprovalRecord.created_at)))
    if a.state != 'approved' or not approval or approval.payload_hash != a.payload_hash or expired(a.expires_at):
        raise HTTPException(409, detail={'code': 'approval_required', 'message': 'Valid approval bound to current payload is required'})
    current_hash = hashlib.sha256(json.dumps({'action_type': a.action_type, 'target': a.target, 'incident_id': a.incident_id}, sort_keys=True).encode()).hexdigest()
    if current_hash != a.payload_hash:
        raise HTTPException(409, detail={'code': 'action_changed', 'message': 'Action payload no longer matches its approval'})
    # The adapter registry intentionally contains no shell or real infrastructure actions.
    adapters = {'lock_synthetic_account': 'simulation.account_lock', 'block_synthetic_ip': 'simulation.ip_block', 'isolate_synthetic_host': 'simulation.host_isolate', 'open_investigation': 'simulation.investigation_open', 'raise_severity': 'simulation.severity_raise', 'add_note': 'simulation.note_added'}
    if a.action_type not in adapters:
        raise HTTPException(422, detail={'code': 'unsupported_action', 'message': 'No adapter is registered'})
    a.state = 'succeeded'
    a.result = json.dumps({'adapter': adapters[a.action_type], 'target': a.target, 'mode': 'simulation-only', 'idempotency_key': idempotency_key})
    db.add(AuditLog(audit_id=str(uuid4()), actor=user['name'], action=adapters[a.action_type], object_type='response_action', object_id=a.action_id, details=a.result))
    db.commit()
    return rowdict(a)

@app.get('/api/v1/audit-logs')
def audit_logs(limit: int=Query(100, ge=1, le=500), db: Session=Depends(get_db)):
    return {'items': [rowdict(x) for x in db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit))]}

@app.get('/api/v1/stream/events')
async def event_stream():

    async def emit():
        last = None
        while True:
            with SessionLocal() as db:
                q = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(1)
                e = db.scalar(q)
                if e and e.event_id != last:
                    last = e.event_id
                    yield ('data: ' + json.dumps(event_dict(e)) + '\n\n')
            await asyncio.sleep(2)
    return StreamingResponse(emit(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.get('/api/v1/overview')
def overview(db: Session=Depends(get_db)):
    count = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    active = db.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(['open', 'investigating', 'contained']))) or 0
    high = db.scalar(select(func.count()).select_from(DetectionFinding).where(DetectionFinding.severity.in_(['high', 'critical']))) or 0
    cats = list(db.execute(select(DetectionRule.name, func.count(DetectionFinding.finding_id)).join(DetectionFinding, DetectionFinding.rule_id == DetectionRule.rule_id).group_by(DetectionRule.name)))
    recent = list(db.scalars(select(Incident).order_by(desc(Incident.updated_at)).limit(6)))
    return {'events_processed': count, 'active_incidents': active, 'high_findings': high, 'detections': [{'name': n, 'count': c} for n, c in cats], 'recent_incidents': [incident_dict(i) for i in recent], 'health': 'operational', 'model': 'cold_start'}

# Serve the compiled console in the single-container public demo; local development
# continues to use the Vite dev server and its API proxy.
WEB_DIST = Path(__file__).resolve().parent.parent / 'frontend' / 'dist'
if WEB_DIST.is_dir():
    app.mount('/assets', StaticFiles(directory=WEB_DIST / 'assets'), name='frontend-assets')

    @app.get('/', include_in_schema=False)
    def dashboard():
        return FileResponse(WEB_DIST / 'index.html')
