from prometheus_client import CollectorRegistry, Histogram, Gauge
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi import APIRouter
from fastapi.responses import Response

registry = CollectorRegistry()

request_duration = Histogram(
    "vivified_request_duration_seconds",
    "Request duration in seconds",
    ["method", "endpoint", "status"],
    registry=registry,
)

active_plugins = Gauge(
    "vivified_active_plugins",
    "Number of active plugins",
    registry=registry,
)

metrics_router = APIRouter()


@metrics_router.get("/metrics")
async def get_metrics():
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
