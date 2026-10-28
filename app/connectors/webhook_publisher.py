"""
Webhook publisher — HMAC-SHA256 signed HTTP POST to subscriber URLs.

Usage:
    from app.connectors.webhook_publisher import publish_event
    await publish_event(db, realm_id="master", event_type="identity.created", payload={...})
"""
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

log = logging.getLogger(__name__)


def _sign_payload(secret: str, payload_bytes: bytes, timestamp: int) -> str:
    """
    Signature = HMAC-SHA256(secret, f"{timestamp}.{payload}")
    Same pattern as Stripe / GitHub webhooks.
    """
    message = f"{timestamp}.".encode() + payload_bytes
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


async def publish_event(
    db: AsyncSession,
    realm_id: str,
    event_type: str,
    payload: dict,
    max_retries: int = 3,
) -> dict:
    """
    Find all active webhook subscriptions that match event_type,
    then POST signed payloads to each.

    Returns summary: { delivered: N, failed: N, skipped: N }
    """
    from app.models.connector import WebhookSubscription
    import httpx

    # Load active subscriptions for this realm
    subs = (await db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.realm_id == realm_id,
            WebhookSubscription.is_active == True,
        )
    )).scalars().all()

    if not subs:
        return {"delivered": 0, "failed": 0, "skipped": 0}

    # Build envelope
    event_id  = str(uuid.uuid4())
    timestamp = int(time.time())
    envelope  = {
        "id":         event_id,
        "type":       event_type,
        "realm_id":   realm_id,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "data":       payload,
    }
    body_bytes = json.dumps(envelope, default=str).encode()

    delivered = failed = skipped = 0

    async with httpx.AsyncClient(timeout=10.0) as client:
        for sub in subs:
            # Check if this subscription cares about this event
            if sub.event_types:
                subscribed = [e.strip() for e in sub.event_types.split(",")]
                # Support wildcard prefix e.g. "identity.*"
                matches = any(
                    event_type == e or
                    (e.endswith(".*") and event_type.startswith(e[:-2]))
                    for e in subscribed
                )
                if not matches:
                    skipped += 1
                    continue

            sig = _sign_payload(sub.secret, body_bytes, timestamp)
            headers = {
                "Content-Type":          "application/json",
                "X-ValoIDM-Event":       event_type,
                "X-ValoIDM-Delivery":    event_id,
                "X-ValoIDM-Signature":   f"sha256={sig}",
                "X-ValoIDM-Timestamp":   str(timestamp),
            }

            last_error = ""
            for attempt in range(max_retries):
                try:
                    r = await client.post(sub.subscriber_url, content=body_bytes, headers=headers)
                    if r.status_code < 300:
                        delivered += 1
                        log.info("Webhook delivered: %s -> %s [%s]",
                                 event_type, sub.subscriber_url, r.status_code)
                        break
                    else:
                        last_error = f"HTTP {r.status_code}"
                except Exception as exc:
                    last_error = str(exc)
                    log.warning("Webhook attempt %d failed for %s: %s",
                                attempt + 1, sub.subscriber_url, exc)
            else:
                failed += 1
                log.error("Webhook delivery failed after %d retries: %s — %s",
                          max_retries, sub.subscriber_url, last_error)

    return {"delivered": delivered, "failed": failed, "skipped": skipped}
