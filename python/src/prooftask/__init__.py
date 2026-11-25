"""ProofTask Agent API SDK for Python: a client generated from the OpenAPI contract, webhook signature verification,
idempotent request IDs, pagination and typed errors. Standard library only.

The ``prooftask.conformity`` subpackage verifies Conformity records and their packaged timestamp evidence offline."""
from . import _generated_types as types
from ._generated_operations import API_BASE_PATH, OPERATIONS
from ._generated_types import API_VERSION
from .client import SDK_VERSION, ProofTaskClient, is_request_id, new_request_id, paginate, request_id_of, with_request_id
from .errors import (AuthenticationError, BadRequestError, ConflictError, NotFoundError, PermissionDeniedError, ProofTaskApiError,
                     ProofTaskError, ProofTaskTransportError, RateLimitError, ServiceUnavailableError, WebhookVerificationError)
from .webhooks import (DEFAULT_TOLERANCE_SECONDS, DELIVERY_ID_HEADER, EVENT_ID_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER, VerifiedWebhook,
                       construct_webhook_event, sign_webhook_payload, verify_webhook_signature)

__all__ = [
    "API_BASE_PATH", "API_VERSION", "OPERATIONS", "SDK_VERSION", "ProofTaskClient", "types",
    "new_request_id", "with_request_id", "is_request_id", "request_id_of", "paginate",
    "ProofTaskError", "ProofTaskApiError", "BadRequestError", "AuthenticationError", "PermissionDeniedError", "NotFoundError",
    "ConflictError", "RateLimitError", "ServiceUnavailableError", "ProofTaskTransportError", "WebhookVerificationError",
    "verify_webhook_signature", "construct_webhook_event", "sign_webhook_payload", "VerifiedWebhook",
    "SIGNATURE_HEADER", "TIMESTAMP_HEADER", "EVENT_ID_HEADER", "DELIVERY_ID_HEADER", "DEFAULT_TOLERANCE_SECONDS",
]
