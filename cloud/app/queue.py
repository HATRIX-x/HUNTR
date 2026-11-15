"""
Hunt job queue — a thin Redis list the API pushes to and workers pull from.

The API `LPUSH`es a job; a worker `BRPOP`s it and runs the hunt in its container.
REDIS_URL is provided by the Railway Redis plugin. If it's unset the queue is
disabled and enqueue raises (so the API fails loudly rather than dropping hunts).
"""
import os, json
from typing import Optional

REDIS_URL = os.environ.get("REDIS_URL", "")
QUEUE_KEY = os.environ.get("HUNT_QUEUE_KEY", "huntr:hunts")

_client = None


def client():
    global _client
    if not REDIS_URL:
        return None
    if _client is None:
        import redis  # lazy import so the app boots even without redis installed
        _client = redis.from_url(REDIS_URL, socket_timeout=10, socket_connect_timeout=10)
    return _client


def enabled() -> bool:
    return bool(REDIS_URL)


def enqueue(job: dict) -> None:
    c = client()
    if not c:
        raise RuntimeError("REDIS_URL not configured — hunt queue unavailable")
    c.lpush(QUEUE_KEY, json.dumps(job))


def depth() -> int:
    c = client()
    return int(c.llen(QUEUE_KEY)) if c else 0


def pop(timeout: int = 5) -> Optional[dict]:
    """Block up to `timeout`s for the next job (worker side)."""
    c = client()
    if not c:
        return None
    res = c.brpop(QUEUE_KEY, timeout=timeout)
    if not res:
        return None
    try:
        return json.loads(res[1])
    except Exception:
        return None
