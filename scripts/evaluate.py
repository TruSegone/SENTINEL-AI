"""Held-out synthetic event-level evaluation of enabled deterministic rules."""
import argparse, json
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sentinel.db import Base
from sentinel.models import SecurityEvent, DetectionFinding
from sentinel.detection import seed_rules, process_event
from sentinel.generator import generate

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--count', type=int, default=1000)
    p.add_argument('--seed', type=int, default=901)
    a = p.parse_args()
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    S = sessionmaker(bind=engine, expire_on_commit=False)
    events = generate(a.count, a.seed, 'heldout-evaluation')
    truth = {e.event_id for e in events if e.outcome in ('failure', 'denied') or e.event_category in ('process', 'identity')}
    predicted = set()
    with S() as db:
        seed_rules(db)
        for payload in events:
            data = payload.model_dump()
            data['observed_at'] = data['observed_at'] or datetime.now(timezone.utc)
            data['raw_event'] = json.dumps(data['raw_event'])
            data['normalized_attributes'] = json.dumps(data['normalized_attributes'])
            event = SecurityEvent(**data)
            db.add(event)
            db.flush()
            findings = process_event(db, event)
            for f in findings:
                predicted.update(json.loads(f.evidence_ids))
            db.commit()
    all_ids = {e.event_id for e in events}
    tn = len(all_ids - truth - predicted)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    tp = len(truth & predicted)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    print(json.dumps({'dataset': 'held-out synthetic scenario', 'seed': a.seed, 'events': a.count, 'label_definition': 'failure/denied outcomes or process/identity category; synthetic heuristic only', 'confusion_matrix': {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn}, 'precision': precision, 'recall': recall, 'f1': f1, 'limitations': ['This is not a real-world effectiveness estimate.', 'Synthetic heuristic labels are imperfect and some rule evidence spans multiple events.', 'Rule thresholds are fixed; no threshold was tuned on this held-out run.', 'Anomaly model is excluded unless separately trained and evaluated.']}, indent=2))
if __name__ == '__main__':
    main()
