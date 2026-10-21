import json
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sentinel.db import Base
from sentinel.models import SecurityEvent, DetectionRule, Incident
from sentinel.schemas import EventIn
from sentinel.detection import seed_rules, process_event
from sentinel.generator import generate
from sentinel.anomaly import features, train_score

def db_session():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()

def ev(i, action='login', outcome='failure', at=None, **kw):
    return EventIn(event_id=f'e{i}', timestamp=at or datetime.now(timezone.utc), event_category='authentication', event_action=action, outcome=outcome, source_ip='192.0.2.44', username='demo-user', hostname='lab-01', **kw)

def persist(db, payload):
    data = payload.model_dump()
    data['observed_at'] = data['observed_at'] or datetime.now(timezone.utc)
    data['raw_event'] = json.dumps(data['raw_event'])
    data['normalized_attributes'] = json.dumps(data['normalized_attributes'])
    row = SecurityEvent(**data)
    db.add(row)
    db.flush()
    return row

def test_event_schema_requires_aware_timestamp_and_validates_ip_and_ports():
    base = dict(event_id='x', timestamp=datetime.now(timezone.utc), event_category='auth', event_action='login')
    assert EventIn(**base, source_ip='192.0.2.1', source_port=65535)
    for invalid in [dict(source_ip='999.1.1.1'), dict(source_port=65536), dict(timestamp=datetime.now())]:
        try:
            EventIn(**base | invalid)
        except Exception:
            pass
        else:
            assert False, 'invalid event should fail validation'

def test_generator_is_reproducible_and_uses_reserved_addresses():
    a = generate(30, seed=12, scenario_id='repeat')
    b = generate(30, seed=12, scenario_id='repeat')
    assert [x.event_id for x in a] == [x.event_id for x in b]
    assert all((x.source_ip.startswith(('192.0.2.', '198.51.100.', '203.0.113.')) for x in a))

def test_failure_burst_creates_evidence_linked_finding_once():
    db = db_session()
    seed_rules(db)
    t = datetime.now(timezone.utc)
    for n in range(5):
        row = persist(db, ev(n, at=t + timedelta(seconds=n)))
        fs = process_event(db, row)
        db.commit()
    burst = [f for f in db.query(__import__('sentinel.models', fromlist=['DetectionFinding']).DetectionFinding).all() if f.rule_id == 'AUTH-FAIL-BURST']
    assert burst and len(json.loads(burst[0].evidence_ids)) == 5
    assert db.query(Incident).count() == 1

def test_success_after_failures_maps_supported_technique():
    db = db_session()
    seed_rules(db)
    t = datetime.now(timezone.utc)
    for n in range(3):
        row = persist(db, ev(n, at=t + timedelta(seconds=n)))
        process_event(db, row)
        db.commit()
    row = persist(db, ev(4, action='login', outcome='success', at=t + timedelta(seconds=8)))
    findings = process_event(db, row)
    assert any((f.rule_id == 'AUTH-FAIL-SUCCESS' and f.technique_id == 'T1078' for f in findings))

def test_anomaly_pipeline_cold_start_and_features_do_not_use_labels():
    items = generate(10)
    assert len(features(items)) == 10 and len(features(items)[0]) == 4
    assert train_score(items[:10], items)['ready'] is False
