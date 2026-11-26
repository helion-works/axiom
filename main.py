"""Axiom — MCP Server Security Scanner"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes import router as api_router, limiter
from app.utils.config import settings
from app.utils.database import init_db
from app.utils.logging import setup_logging, get_logger

logger = get_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    json_logs = settings.APP_ENV == "production"
    setup_logging(level=settings.LOG_LEVEL, json_output=json_logs)
    logger.info("Axiom starting", extra={"target": settings.APP_ENV})
    await init_db()
    yield
    logger.info("Axiom shutting down")


app = FastAPI(
    title="Axiom",
    description="Security Scanner for MCP (Model Context Protocol) Servers",
    version="0.6.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: restrict origins in production, allow all only in development
if settings.APP_ENV == "production":
    allowed_origins = settings.CORS_ALLOWED_ORIGINS
    if not allowed_origins:
        logger.warning(
            "CORS_ALLOWED_ORIGINS not set in production — "
            "defaulting to https://helionworks.com only"
        )
        allowed_origins = ["https://helionworks.com"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

templates = Jinja2Templates(directory="frontend/templates")
app.include_router(api_router, prefix="/api/v1")


@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/health")
async def health():
    from app.utils.config import current_env, explicit_host_access

    return {
        "status": "healthy",
        "service": "Axiom",
        "version": "0.6.0",
        "env": current_env(),
        "host_access": explicit_host_access(),
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.APP_HOST, port=settings.APP_PORT, reload=settings.APP_DEBUG)
