"""Webhook signature verification, as docs/developers/PROJECT_EVENTS.md specifies.

``prooftask-signature`` is ``v1=`` followed by the lowercase hex HMAC-SHA256 of ``timestamp + "." + raw body``,
keyed by the subscription secret. ``prooftask-timestamp`` is Unix seconds; reject it when more than five minutes
away from now. Signatures are compared in constant time, over the exact raw bytes, before any JSON parsing.
A valid signature is not current project authority: read the project before acting, and deduplicate by
``prooftask-event-id`` because retries repeat events.
"""
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, Mapping, Optional, Union

from .errors import WebhookVerificationError

SIGNATURE_HEADER = "prooftask-signature"
TIMESTAMP_HEADER = "prooftask-timestamp"
EVENT_ID_HEADER = "prooftask-event-id"
DELIVERY_ID_HEADER = "prooftask-delivery-id"
DEFAULT_TOLERANCE_SECONDS = 300

_TIMESTAMP = re.compile(r"^[0-9]{1,12}$")
_SIGNATURE = re.compile(r"^v1=[a-f0-9]{64}$")


def _bytes(value: Union[str, bytes, bytearray, memoryview]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def sign_webhook_payload(secret: str, timestamp: str, raw_body: Union[str, bytes]) -> str:
    """The ``v1=`` signature ProofTask sends for these bytes. Useful to test a receiver."""
    return "v1=" + hmac.new(secret.encode("utf-8"), timestamp.encode("utf-8") + b"." + _bytes(raw_body), hashlib.sha256).hexdigest()


def verify_webhook_signature(secret: str, raw_body: Union[str, bytes], timestamp: Optional[str], signature: Optional[str],
                             now: Optional[float] = None, tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS) -> None:
    """Raise WebhookVerificationError unless the signature and timestamp are valid. ``now`` is Unix seconds."""
    if not isinstance(secret, str) or not secret:
        raise TypeError("secret is required")
    if not timestamp:
        raise WebhookVerificationError("MISSING_HEADER", "Missing prooftask-timestamp header")
    if not signature:
        raise WebhookVerificationError("MISSING_HEADER", "Missing prooftask-signature header")
    if not _TIMESTAMP.match(timestamp):
        raise WebhookVerificationError("TIMESTAMP_INVALID", "prooftask-timestamp must be Unix seconds")
    current = time.time() if now is None else now
    if abs(current - int(timestamp)) > tolerance_seconds:
        raise WebhookVerificationError("TIMESTAMP_OUT_OF_TOLERANCE", "prooftask-timestamp is more than %d seconds from now" % tolerance_seconds)
    if not _SIGNATURE.match(signature):
        raise WebhookVerificationError("SIGNATURE_FORMAT_INVALID", "prooftask-signature must be v1= followed by 64 lowercase hex characters")
    if not hmac.compare_digest(sign_webhook_payload(secret, timestamp, raw_body), signature):
        raise WebhookVerificationError("SIGNATURE_MISMATCH", "Signature does not match this secret and body")


def _header(headers: Mapping[str, Any], name: str) -> Optional[str]:
    getter = getattr(headers, "get", None)
    # email.message.Message (http.server) and similar mappings are case-insensitive already.
    if getter is not None and not isinstance(headers, dict):
        value = getter(name)
        return value if isinstance(value, str) else None
    for key, value in headers.items():
        if key.lower() == name:
            return value if isinstance(value, str) else None
    return None


class VerifiedWebhook:
    """A verified request: identifiers and the parsed body. ``is_test`` requests must be acknowledged, not acted on."""

    def __init__(self, event_id: str, delivery_id: str, timestamp: int, event: Dict[str, Any]) -> None:
        self.event_id = event_id
        self.delivery_id = delivery_id
        self.timestamp = timestamp
        self.event = event
        self.is_test = isinstance(event, dict) and event.get("type") == "webhook.test"


def construct_webhook_event(secret: str, raw_body: Union[str, bytes], headers: Mapping[str, Any],
                            now: Optional[float] = None, tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS) -> VerifiedWebhook:
    """Verify a received request and return its identifiers and parsed body."""
    timestamp, signature = _header(headers, TIMESTAMP_HEADER), _header(headers, SIGNATURE_HEADER)
    verify_webhook_signature(secret, raw_body, timestamp, signature, now=now, tolerance_seconds=tolerance_seconds)
    event_id, delivery_id = _header(headers, EVENT_ID_HEADER), _header(headers, DELIVERY_ID_HEADER)
    if not event_id or not delivery_id:
        raise WebhookVerificationError("MISSING_HEADER", "Missing prooftask-event-id or prooftask-delivery-id header")
    try:
        event = json.loads(_bytes(raw_body).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebhookVerificationError("BODY_NOT_JSON", "Body is not JSON") from None
    return VerifiedWebhook(event_id, delivery_id, int(timestamp or 0), event)
