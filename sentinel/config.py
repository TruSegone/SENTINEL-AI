import os
DATABASE_URL = os.getenv('SENTINEL_DATABASE_URL', 'sqlite:///./sentinel.db')
DEMO_TOKEN = os.getenv('SENTINEL_DEMO_TOKEN', 'demo-analyst')
CORS_ORIGINS = [x.strip() for x in os.getenv('SENTINEL_CORS_ORIGINS', 'http://localhost:5173').split(',') if x.strip()]
REPLAY_DELAY = float(os.getenv('SENTINEL_REPLAY_DELAY', '0.05'))
