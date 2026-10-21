"""Versioned deterministic detectors; mapped ATT&CK techniques are hypotheses."""
import hashlib, json
from datetime import timedelta, timezone
from uuid import uuid4
from sqlalchemy import select
from .models import DetectionRule, DetectionFinding, SecurityEvent, Incident, IncidentEvent, AuditLog, now
# ATT&CK labels describe the supported detector behavior, not proof of an attack.
RULES = [
    {
        "rule_id": "AUTH-FAIL-BURST",
        "name": "Authentication failure burst",
        "version": "1.0",
        "description": "Five failed logins by one identity and source within five minutes.",
        "severity": "high",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    {
        "rule_id": "AUTH-FAIL-SUCCESS",
        "name": "Successful login after failure burst",
        "version": "1.0",
        "description": "A successful login follows three failures for the same identity and source within ten minutes.",
        "severity": "critical",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    {
        "rule_id": "ACCESS-DENIED-BURST",
        "name": "Repeated access denied",
        "version": "1.0",
        "description": "Eight denied requests from one source within two minutes.",
        "severity": "medium",
        "technique_id": None,
        "technique_name": None,
    },
    {
        "rule_id": "USER-NEW-IP",
        "name": "New source IP for synthetic user",
        "version": "1.0",
        "description": "A synthetic identity authenticates from an IP absent from its stored baseline.",
        "severity": "medium",
        "technique_id": None,
        "technique_name": None,
    },
    {
        "rule_id": "PROCESS-UNUSUAL",
        "name": "Unusual process execution",
        "version": "1.0",
        "description": "A synthetic host executed a shell-like process.",
        "severity": "medium",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    {
        "rule_id": "PRIV-CHANGE",
        "name": "Privilege change signal",
        "version": "1.0",
        "description": "A privilege change event requires analyst review.",
        "severity": "high",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
    },
    {
        "rule_id": "OUTBOUND-DNS",
        "name": "Unusual outbound DNS activity",
        "version": "1.0",
        "description": "Repeated DNS activity from one source within five minutes.",
        "severity": "low",
        "technique_id": "T1071.004",
        "technique_name": "DNS",
    },
    {
        "rule_id": "MULTI-HOST",
        "name": "Cross-host related activity",
        "version": "1.0",
        "description": "Related source activity spans at least three hosts within ten minutes.",
        "severity": "high",
        "technique_id": None,
        "technique_name": None,
    },
]


def seed_rules(db):
    for r in RULES:
        if not db.get(DetectionRule, r['rule_id']):
            db.add(DetectionRule(**r, enabled=True))
    db.commit()

def _scope(stmt, event):
    """Keep live traffic and each replay session's temporal windows isolated."""
    return stmt.where(SecurityEvent.replay_id == event.replay_id) if event.replay_id else stmt.where(SecurityEvent.replay_id.is_(None))

def _iso(value):
    value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return value.isoformat()

def _finding(db, rule_id, title, severity, confidence, explanation, events):
    ids = [e.event_id for e in events]
    replay_id = events[-1].replay_id
    # Include the replay session in the key so independent runs do not collapse together.
    dedupe = hashlib.sha256((rule_id + ':' + (replay_id or 'live') + ':' + ':'.join(sorted(ids))).encode()).hexdigest()
    existing = db.scalar(select(DetectionFinding).where(DetectionFinding.dedupe_key == dedupe))
    if existing:
        return existing
    rule = db.get(DetectionRule, rule_id)
    finding = DetectionFinding(finding_id=str(uuid4()), rule_id=rule_id, title=title, severity=severity, confidence=confidence, explanation=explanation, evidence_ids=json.dumps(ids), evidence=json.dumps([{'event_id': e.event_id, 'timestamp': _iso(e.timestamp), 'action': e.event_action, 'source_ip': e.source_ip, 'username': e.username, 'hostname': e.hostname} for e in events]), dedupe_key=dedupe, technique_id=rule.technique_id, technique_name=rule.technique_name, replay_id=replay_id)
    db.add(finding)
    db.flush()
    entity = events[-1].username or events[-1].source_ip or events[-1].hostname or 'synthetic-activity'
    # Correlation is by rule and entity; it asserts association, not causation.
    key = f'finding:{rule_id}:{entity}' + (f':replay:{replay_id}' if replay_id else '')
    incident = db.scalar(select(Incident).where(Incident.correlation_key == key))
    if not incident:
        incident = Incident(incident_id=str(uuid4()), title=title, severity=severity, status='open', correlation_key=key, summary=explanation, created_at=now(), updated_at=now())
        db.add(incident)
        db.flush()
        db.add(AuditLog(audit_id=str(uuid4()), actor='sentinel-processor', action='incident.opened', object_type='incident', object_id=incident.incident_id, details=explanation))
    finding.incident_id = incident.incident_id
    for e in events:
        if not db.scalar(select(IncidentEvent).where(IncidentEvent.incident_id == incident.incident_id, IncidentEvent.event_id == e.event_id)):
            db.add(IncidentEvent(incident_id=incident.incident_id, event_id=e.event_id))
    return finding

def process_event(db, event):
    """Apply bounded, deterministic rules to one persisted normalized event."""
    findings = []
    if event.event_category.lower() in ('authentication', 'auth') and event.outcome == 'failure' and event.username and event.source_ip:
        recent = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.event_category.in_(['authentication', 'auth']), SecurityEvent.outcome == 'failure', SecurityEvent.username == event.username, SecurityEvent.source_ip == event.source_ip, SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=5), SecurityEvent.timestamp <= event.timestamp), event).order_by(SecurityEvent.timestamp.desc()).limit(20)))
        if len(recent) >= 5:
            findings.append(_finding(db, 'AUTH-FAIL-BURST', 'Authentication failure burst', 'high', 0.86, f'{len(recent)} failed authentications for {event.username} from {event.source_ip} within five minutes.', recent))
    if event.event_category.lower() in ('authentication', 'auth') and event.outcome == 'success' and event.username and event.source_ip:
        prior_user = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.event_category.in_(['authentication', 'auth']), SecurityEvent.username == event.username, SecurityEvent.timestamp < event.timestamp), event).limit(500)))
        known = {x.source_ip for x in prior_user if x.source_ip}
        if known and event.source_ip not in known:
            findings.append(_finding(db, 'USER-NEW-IP', 'New source IP for synthetic user', 'medium', 0.62, f'{event.username} authenticated from an IP not present in the stored user baseline.', [event]))
        prior = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.event_category.in_(['authentication', 'auth']), SecurityEvent.outcome == 'failure', SecurityEvent.username == event.username, SecurityEvent.source_ip == event.source_ip, SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=10), SecurityEvent.timestamp < event.timestamp), event).order_by(SecurityEvent.timestamp.desc()).limit(20)))
        if len(prior) >= 3:
            findings.append(_finding(db, 'AUTH-FAIL-SUCCESS', 'Successful login after failure burst', 'critical', 0.93, f'A success followed {len(prior)} failures for the same account and source.', prior + [event]))
    if event.outcome == 'denied' and event.source_ip:
        rows = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.outcome == 'denied', SecurityEvent.source_ip == event.source_ip, SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=2), SecurityEvent.timestamp <= event.timestamp), event).limit(20)))
        if len(rows) >= 8:
            findings.append(_finding(db, 'ACCESS-DENIED-BURST', 'Repeated access denied', 'medium', 0.78, f'{len(rows)} denied requests from {event.source_ip} in two minutes.', rows))
    if event.event_category == 'process' and any((x in (event.process_name or '').lower() for x in ('powershell', 'bash', 'sh', 'cmd.exe'))):
        findings.append(_finding(db, 'PROCESS-UNUSUAL', 'Unusual process execution', 'medium', 0.68, f"Shell-like process {event.process_name} ran on {event.hostname or 'an unspecified host'}; review context.", [event]))
    if event.event_action in ('privilege_change', 'role_elevated'):
        related = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.username == event.username, SecurityEvent.event_category == 'process', SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=10), SecurityEvent.timestamp < event.timestamp), event).order_by(SecurityEvent.timestamp.desc()).limit(10))) if event.username else []
        evidence = related + [event]
        findings.append(_finding(db, 'PRIV-CHANGE', 'Privilege change signal', 'high', 0.81 if related else 0.72, f"Privilege change recorded for {event.username or 'an unspecified identity'}" + (' after a process event within ten minutes.' if related else '; preceding process context was not available.'), evidence))
    if event.source_ip and event.event_category in ('authentication', 'auth', 'process', 'dns'):
        related = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.source_ip == event.source_ip, SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=10), SecurityEvent.timestamp <= event.timestamp), event).limit(100)))
        hosts = {x.hostname for x in related if x.hostname}
        if len(hosts) >= 3:
            findings.append(_finding(db, 'MULTI-HOST', 'Related activity across multiple hosts', 'high', 0.75, f'Related events from {event.source_ip} span {len(hosts)} hosts in ten minutes; temporal association only.', related))
    if event.event_category == 'dns' and event.source_ip:
        rows = list(db.scalars(_scope(select(SecurityEvent).where(SecurityEvent.event_category == 'dns', SecurityEvent.source_ip == event.source_ip, SecurityEvent.timestamp >= event.timestamp - timedelta(minutes=5), SecurityEvent.timestamp <= event.timestamp), event).limit(20)))
        if len(rows) >= 4:
            findings.append(_finding(db, 'OUTBOUND-DNS', 'Repeated DNS activity', 'low', 0.55, f'{len(rows)} DNS events from {event.source_ip}; generated test-domain activity only.', rows))
    return findings
