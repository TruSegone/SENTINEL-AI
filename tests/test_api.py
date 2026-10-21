from fastapi.testclient import TestClient
from sentinel.main import app
from sentinel.db import SessionLocal
from sentinel.models import Incident
from uuid import uuid4

def test_health_and_readiness():
    with TestClient(app) as client:
        assert client.get('/health').status_code == 200
        assert client.get('/ready').json()['status'] == 'ready'

def test_event_write_requires_demo_token_and_validates_payload():
    with TestClient(app) as client:
        event = {'event_id': 'api-auth-check', 'timestamp': '2026-01-01T00:00:00Z', 'event_category': 'authentication', 'event_action': 'login'}
        assert client.post('/api/v1/events', json=event).status_code == 401
        headers = {'X-Analyst-Token': 'demo-analyst'}
        assert client.post('/api/v1/events', json={}, headers=headers).status_code == 422

def test_api_exposes_rules_and_bounded_graph():
    with TestClient(app) as client:
        assert client.get('/api/v1/rules').status_code == 200
        graph = client.get('/api/v1/entities/graph?limit=10').json()
        assert len(graph['nodes']) <= 10

def test_response_action_cannot_execute_without_approval():
    with TestClient(app) as client:
        iid = str(uuid4())
        with SessionLocal() as db:
            db.add(Incident(incident_id=iid, title='test incident', severity='medium', status='open', correlation_key='test:' + iid, summary='synthetic test'))
            db.commit()
        headers = {'X-Analyst-Token': 'demo-analyst', 'X-Analyst-Role': 'admin'}
        proposed = client.post(f'/api/v1/incidents/{iid}/response-actions?action_type=open_investigation&target=demo-test', headers=headers)
        assert proposed.status_code == 201
        result = client.post(f"/api/v1/response-actions/{proposed.json()['action_id']}/execute", headers=headers)
        assert result.status_code == 409
