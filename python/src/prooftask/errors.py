"""Typed errors. Branch on ``code`` (the API's stable error code) or on the class."""
from typing import Any, Dict, Optional, Union


class ProofTaskError(Exception):
    """Base class of every error this package raises."""


class ProofTaskApiError(ProofTaskError):
    """The server answered with a non-success HTTP status."""

    def __init__(self, operation_id: str, status: int, body: Union[Dict[str, Any], str, None], retry_after: Optional[int]) -> None:
        parsed = body if isinstance(body, dict) else {}
        self.operation_id = operation_id
        self.status = status
        self.body = body
        self.retry_after = retry_after
        #: Stable error code from the body's ``error`` field, or ``HTTP_<status>``.
        self.code: str = parsed["error"] if isinstance(parsed.get("error"), str) else "HTTP_%d" % status
        self.next_action: Optional[str] = parsed.get("nextAction") if isinstance(parsed.get("nextAction"), str) else None
        self.field: Optional[str] = parsed.get("field") if isinstance(parsed.get("field"), str) else None
        self.detail: Optional[str] = parsed.get("detail") if isinstance(parsed.get("detail"), str) else None
        self.reason: Optional[str] = parsed.get("reason") if isinstance(parsed.get("reason"), str) else None
        self.human_url: Optional[str] = parsed.get("humanUrl") if isinstance(parsed.get("humanUrl"), str) else None
        extra = self.detail or self.reason
        super().__init__("%s failed with HTTP %d: %s%s" % (operation_id, status, self.code, " (%s)" % extra if extra else ""))


class BadRequestError(ProofTaskApiError):
    """400 or 413: malformed, too large or invalid. Fix the field named in ``field``."""


class AuthenticationError(ProofTaskApiError):
    """401: the credential is missing, expired or revoked."""


class PermissionDeniedError(ProofTaskApiError):
    """403: the credential's authority does not cover this action."""


class NotFoundError(ProofTaskApiError):
    """404: not found, or not visible to this credential."""


class ConflictError(ProofTaskApiError):
    """409: stale expected state, a reused request ID with different content, or a state that does not allow the action."""


class RateLimitError(ProofTaskApiError):
    """429: rate limited. ``retry_after`` gives the wait in seconds when the server sent one."""


class ServiceUnavailableError(ProofTaskApiError):
    """5xx: the service could not answer."""


def api_error(operation_id: str, status: int, body: Union[Dict[str, Any], str, None], retry_after: Optional[int]) -> ProofTaskApiError:
    if status in (400, 413):
        kind = BadRequestError
    elif status == 401:
        kind = AuthenticationError
    elif status == 403:
        kind = PermissionDeniedError
    elif status == 404:
        kind = NotFoundError
    elif status == 409:
        kind = ConflictError
    elif status == 429:
        kind = RateLimitError
    elif status >= 500:
        kind = ServiceUnavailableError
    else:
        kind = ProofTaskApiError
    return kind(operation_id, status, body, retry_after)


class ProofTaskTransportError(ProofTaskError):
    """No usable HTTP answer. For a write ``outcome_unknown`` is True: resend the same body with the same requestId."""

    def __init__(self, operation_id: str, outcome_unknown: bool, cause: BaseException) -> None:
        self.operation_id = operation_id
        self.outcome_unknown = outcome_unknown
        super().__init__("%s: no usable response%s" % (operation_id, "; the outcome is unknown, resend the same body with the same requestId" if outcome_unknown else ""))
        self.__cause__ = cause


class WebhookVerificationError(ProofTaskError):
    """A webhook request failed signature or freshness checks. Do not act on its body.

    ``code`` is one of MISSING_HEADER, TIMESTAMP_INVALID, TIMESTAMP_OUT_OF_TOLERANCE,
    SIGNATURE_FORMAT_INVALID, SIGNATURE_MISMATCH or BODY_NOT_JSON."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)
