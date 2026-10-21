"""Optional Isolation Forest anomaly scorer. Scores are not probabilities."""
from collections import Counter
FEATURE_SCHEMA = ['utc_hour', 'source_frequency', 'category_code', 'outcome_code']
CATEGORIES = {'authentication': 1, 'auth': 1, 'web': 2, 'process': 3, 'identity': 4, 'dns': 5}
OUTCOMES = {'success': 0, 'failure': 1, 'denied': 2}

def features(events):
    """Extract inference-only attributes; scenario labels never enter the feature set."""
    source_counts = Counter((e.source_ip for e in events if e.source_ip))
    return [[e.timestamp.hour, source_counts.get(e.source_ip, 0), CATEGORIES.get(e.event_category, 0), OUTCOMES.get(e.outcome, 0)] for e in events]

def train_score(benign_events, events, contamination=0.05):
    """Fit only against caller-supplied benign baseline; scores are not probabilities."""
    if len(benign_events) < 32:
        return {'ready': False, 'reason': 'cold_start: at least 32 benign events are required', 'scores': []}
    try:
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(n_estimators=100, contamination=contamination, random_state=19)
        model.fit(features(benign_events))
        return {'ready': True, 'algorithm': 'IsolationForest', 'version': '1.0', 'feature_schema': FEATURE_SCHEMA, 'scores': [float(max(0, min(1, (0.25 - model.decision_function([x])[0]) / 0.5))) for x in features(events)]}
    except ImportError:
        return {'ready': False, 'reason': 'scikit-learn unavailable', 'scores': []}
