import asyncio
import logging
import psycopg
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings, DEFAULT_JWT_SECRET
from backend.core.claude_engine import resolve_provider
from backend.models import DDL_STATEMENTS
from backend.api.routes_ingest import router as ingest_router
from backend.api.routes_auth import router as auth_router
from backend.api.routes_alerts import router as alerts_router
from backend.api.routes_ws import router as ws_router
from backend.core.ws_manager import ws_manager


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Hand the running event loop to the WS manager so background threads can broadcast
    ws_manager.set_loop(asyncio.get_running_loop())

    log = logging.getLogger("alertiq")
    log.info(f"[startup] AI triage provider: {resolve_provider()}")
    if settings.jwt_secret == DEFAULT_JWT_SECRET:
        log.warning("[startup] JWT_SECRET is the default value. Set your own in .env before deploying.")
    if not settings.ingest_api_key:
        log.warning("[startup] INGEST_API_KEY not set: anyone who can reach the API can post alerts.")

    if not app.state.testing:
        with psycopg.connect(settings.database_url) as conn:
            for stmt in DDL_STATEMENTS:
                conn.execute(stmt)
    yield


app = FastAPI(
    title="AlertIQ",
    description="AI-Powered SIEM Alert Triage System",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.testing = False

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)
app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(ws_router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "service": "AlertIQ"}
