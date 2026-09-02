import logging
import os
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .database import (
    BASE_DIR,
    DOWNLOAD_DIR,
    SCANS_DIR,
    initialize_database,
    get_application_state,
    redis_client,
)
from .config import (
    environment_list,
    validate_runtime_configuration,
    validate_server_bind,
)
from .auth import (
    AUTH_REQUIRED,
    ensure_bootstrap_admin,
    ensure_development_admin,
)
from .observability import (
    ObservabilityMiddleware,
    configure_logging,
)
from .rate_limit import RateLimitMiddleware
from .security_middleware import (
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    WafASGIMiddleware,
)
from .web_common import (
    DEMO_LAB_ENABLED,
    MAX_REQUEST_BYTES,
    load_waf_rules_from_db,
    parse_cors_origins,
    require_demo_lab_access,
)
from . import web_common
from .health_routes import router as health_router

router = APIRouter()
logger = logging.getLogger("aegis.main")

# Enable CORS for convenience.

if DEMO_LAB_ENABLED:
    from .demo_lab import router as demo_lab_router

    router.include_router(
        demo_lab_router,
        prefix="/demo-lab",
        dependencies=[Depends(require_demo_lab_access)],
    )

from .routes.auth_routes import router as auth_router
from .routes.project_routes import router as project_router
from .routes.github_routes import router as github_router
from .routes.admin_routes import router as admin_router
from .routes.artifact_routes import router as artifact_router
from .routes.demo_scan_routes import router as demo_scan_router

router.include_router(auth_router)
router.include_router(project_router)
router.include_router(github_router)
router.include_router(admin_router)
router.include_router(artifact_router)
router.include_router(demo_scan_router)

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize mutable runtime state only when the ASGI app starts."""
    validate_runtime_configuration()
    configure_logging()
    DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
    SCANS_DIR.mkdir(exist_ok=True, parents=True)

    sample_file = DOWNLOAD_DIR / "sample.txt"
    if not sample_file.exists():
        sample_file.write_text("This is a safe sample file.\n")

    initialize_database()
    ensure_bootstrap_admin()
    ensure_development_admin()
    web_common.WAF_ENABLED = bool(
        get_application_state("waf_enabled", web_common.WAF_ENABLED)
    )
    application.state.secret_key = os.environ.get("SECRET_KEY")
    yield


def create_app() -> FastAPI:
    """Build a fully configured Aegis ASGI application."""
    application = FastAPI(title="Aegis DevSecOps Console", lifespan=lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=parse_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    allowed_hosts = environment_list("AEGIS_ALLOWED_HOSTS")
    if allowed_hosts:
        application.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    application.mount(
        "/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static"
    )
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(RateLimitMiddleware, redis_client=redis_client)
    application.add_middleware(ObservabilityMiddleware)
    application.add_middleware(
        WafASGIMiddleware,
        enabled=lambda: web_common.WAF_ENABLED,
        load_rules=load_waf_rules_from_db,
    )
    application.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)
    application.include_router(router)
    application.include_router(health_router)
    return application

app = create_app()


if __name__ == "__main__":
    import uvicorn
    host = validate_server_bind(
        os.environ.get("AEGIS_HOST", "127.0.0.1"),
        auth_required=AUTH_REQUIRED,
    )
    uvicorn.run("app.main:app", host=host, port=5001, reload=False)
