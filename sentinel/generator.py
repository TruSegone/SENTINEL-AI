"""Deterministic synthetic telemetry generator using documentation-only addresses."""
from datetime import datetime, timedelta, timezone
import random
from uuid import uuid5, NAMESPACE_DNS
from .schemas import EventIn

def generate(count=300, seed=7, scenario_id='credential-chain'):
    """Generate stable IDs and reserved documentation IPs for a seeded scenario."""
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(minutes=25)
    out = []
    users = ['analyst01', 'svc-backup', 'buildbot', 'demo-user']
    hosts = ['lab-ws-01', 'lab-app-02', 'lab-db-01', 'lab-jump-01']
    for i in range(count):
        ts = start + timedelta(seconds=i * 2)
        if i % 47 in range(10, 16):
            category, action, outcome, user, ip = ('authentication', 'login', 'failure', 'demo-user', '192.0.2.44')
        elif i % 47 == 16:
            category, action, outcome, user, ip = ('authentication', 'login', 'success', 'demo-user', '192.0.2.44')
        elif i % 83 == 22:
            category, action, outcome, user, ip = ('process', 'process_start', 'success', rng.choice(users), '198.51.100.17')
        elif i % 91 == 24:
            category, action, outcome, user, ip = ('identity', 'privilege_change', 'success', rng.choice(users), '198.51.100.17')
        elif i % 23 == 4:
            category, action, outcome, user, ip = ('web', 'request', 'denied', rng.choice(users), '203.0.113.9')
        elif i % 31 == 8:
            category, action, outcome, user, ip = ('dns', 'query', 'success', rng.choice(users), '192.0.2.80')
        else:
            category, action, outcome, user, ip = ('authentication', 'login', 'success', rng.choice(users), f'192.0.2.{rng.randint(1, 200)}')
        host = hosts[i // 9 % len(hosts)]
        eid = str(uuid5(NAMESPACE_DNS, f'sentinel:{seed}:{scenario_id}:{i}'))
        out.append(
            EventIn(
                event_id=eid,
                timestamp=ts,
                event_category=category,
                event_action=action,
                outcome=outcome,
                severity='high' if outcome == 'failure' else 'low',
                source_ip=ip,
                username=user,
                hostname=host,
                process_name='powershell.exe' if category == 'process' else None,
                command_line=(
                    'powershell -NoProfile -File synthetic.ps1'
                    if category == 'process'
                    else None
                ),
                event_source='synthetic-generator',
                scenario_id=scenario_id,
                raw_event={'generator_seed': seed, 'sequence': i},
                normalized_attributes={'generator': 'sentinel-v1'},
            )
        )
    return out
