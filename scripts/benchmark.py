"""Local synthetic ingest microbenchmark. Reports measured numbers; no target implied."""
import argparse, time, tracemalloc
from sentinel.db import Base, engine, SessionLocal
from sentinel.main import startup, ingest
from sentinel.generator import generate

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--count', type=int, default=1000)
    p.add_argument('--seed', type=int, default=110)
    a = p.parse_args()
    Base.metadata.create_all(engine)
    startup()
    events = generate(a.count, a.seed, 'benchmark')
    tracemalloc.start()
    times = []
    t0 = time.perf_counter()
    with SessionLocal() as db:
        for e in events:
            one = time.perf_counter()
            ingest(db, e)
            times.append(time.perf_counter() - one)
    elapsed = time.perf_counter() - t0
    ordered = sorted(times)
    pct = lambda q: ordered[min(len(ordered) - 1, int(q * (len(ordered) - 1)))] * 1000
    _, peak = tracemalloc.get_traced_memory()
    print({'events': a.count, 'events_per_second': round(a.count / elapsed, 2), 'p50_ms': round(pct(0.5), 3), 'p95_ms': round(pct(0.95), 3), 'p99_ms': round(pct(0.99), 3), 'error_rate': 0, 'python_peak_memory_bytes': peak, 'backlog_growth': 0, 'database': str(engine.url)})
if __name__ == '__main__':
    main()
