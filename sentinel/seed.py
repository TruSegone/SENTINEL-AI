import argparse
from .db import Base, engine, SessionLocal
from .main import startup, ingest
from .generator import generate

def main():
    p = argparse.ArgumentParser(description='Load repeatable synthetic Sentinel telemetry')
    p.add_argument('--count', type=int, default=500)
    p.add_argument('--seed', type=int, default=7)
    p.add_argument('--scenario', default='seed-demo')
    args = p.parse_args()
    Base.metadata.create_all(engine)
    startup()
    accepted = 0
    with SessionLocal() as db:
        for e in generate(args.count, args.seed, args.scenario):
            accepted += ingest(db, e)[0]
    print(f'accepted={accepted} requested={args.count} scenario={args.scenario}')
if __name__ == '__main__':
    main()
