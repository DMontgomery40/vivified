from prometheus_client import CollectorRegistry, Histogram, Gauge, Counter
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

notifications_sends_total = Counter(
    "vivified_notifications_sends_total",
    "Total notification requests received",
    ["source"],
    registry=registry,
)

notifications_sent_total = Counter(
    "vivified_notifications_sent_total",
    "Total notifications marked sent",
    registry=registry,
)

notifications_failed_total = Counter(
    "vivified_notifications_failed_total",
    "Total notifications marked failed",
    registry=registry,
)

notifications_send_latency = Histogram(
    "vivified_notifications_send_latency_seconds",
    "Latency for handling a notification send request",
    registry=registry,
)

metrics_router = APIRouter()


@metrics_router.get("/metrics")
async def get_metrics():
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
