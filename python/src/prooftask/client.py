"""The Agent API client: generated operation methods over a small standard-library transport."""
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, Iterator, Optional

from ._generated_operations import API_BASE_PATH, OPERATIONS, GeneratedOperations
from .errors import ProofTaskTransportError, api_error

SDK_VERSION = "0.1.4"
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_UUID_V4 = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")


def new_request_id() -> str:
    """A fresh lowercase version 4 UUID for a write's ``requestId``.

    Save the complete body with this ID before sending; after an uncertain result resend that exact body.
    The server replays the same answer for the same ID and body and rejects different content under that ID."""
    return str(uuid.uuid4())


def is_request_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID_V4.match(value))


def with_request_id(body: Dict[str, Any]) -> Dict[str, Any]:
    """The body with a ``requestId``; an existing one is kept, so calling this again on a saved body never changes it."""
    if "requestId" in body:
        if not is_request_id(body["requestId"]):
            raise TypeError("requestId must be a lowercase version 4 UUID")
        return body
    return {**body, "requestId": new_request_id()}


def request_id_of(body: Any) -> Optional[str]:
    """The request ID a body carries (``requestId``, or ``input.requestId`` for project command envelopes)."""
    if not isinstance(body, dict):
        return None
    if is_request_id(body.get("requestId")):
        return body["requestId"]
    nested = body.get("input")
    if isinstance(nested, dict) and is_request_id(nested.get("requestId")):
        return nested["requestId"]
    return None


def paginate(fetch_page: Callable[[Optional[str]], Dict[str, Any]], after: Optional[str] = None) -> Iterator[Dict[str, Any]]:
    """Yield every page of a cursor list (``rows`` and ``next``), following ``next`` until it is None.

    A page can hold fewer rows than the maximum while ``next`` is set, so always follow ``next``. Never build cursors."""
    seen = set()
    cursor = after
    while True:
        page = fetch_page(cursor)
        yield page
        following = page.get("next")
        if following is None:
            return
        if following in seen:
            raise RuntimeError("PAGINATION_CURSOR_REPEATED")
        seen.add(following)
        cursor = following


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


def _checked_origin(value: str) -> str:
    url = urllib.parse.urlsplit(value)
    if url.path not in ("", "/") or url.query or url.fragment or url.username or url.password or not url.hostname:
        raise ValueError("origin must be a bare origin such as https://prooftask.com")
    if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOOPBACK):
        raise ValueError("origin must use https (http is accepted only for a loopback test server)")
    return "%s://%s" % (url.scheme, url.netloc)


class ProofTaskClient(GeneratedOperations):
    """Agent API client. Methods are generated from the OpenAPI contract and take keyword arguments:
    path and query parameters by name (snake_case) and the JSON request ``body``.

    ``max_retries`` retries network failures, timeouts, 429 and 503; a write is retried only when its body carries a
    requestId, so a retry is always the same idempotent request."""

    def __init__(self, token: Optional[str] = None, origin: str = "https://prooftask.com", timeout: float = 30.0,
                 max_retries: int = 2, user_agent: Optional[str] = None) -> None:
        self.origin = _checked_origin(origin)
        if token is not None and (not token or any(c.isspace() for c in token)):
            raise ValueError("token must be a non-empty string without spaces")
        self._token = token
        self._timeout = timeout
        self._max_retries = max_retries
        self._user_agent = "prooftask-sdk-python/%s%s" % (SDK_VERSION, " " + user_agent if user_agent else "")
        self._opener = urllib.request.build_opener(_NoRedirect)

    @property
    def api_base_url(self) -> str:
        return self.origin + API_BASE_PATH

    def url(self, operation: str, args: Dict[str, Any]) -> str:
        spec = OPERATIONS[operation]

        def substitute(match: "re.Match[str]") -> str:
            value = args.get(match.group(1))
            if not isinstance(value, str) or not value:
                raise TypeError("%s: path parameter %s is required" % (operation, match.group(1)))
            return urllib.parse.quote(value, safe="")

        path = re.sub(r"\{([^}]+)\}", substitute, spec["path"])
        query = [(name, str(args[name])) for name in spec["queryParams"] if args.get(name) is not None]
        return self.origin + spec["basePath"] + path + ("?" + urllib.parse.urlencode(query) if query else "")

    def _call(self, operation: str, args: Dict[str, Any], options: Optional[Dict[str, Any]]) -> Any:
        spec, options = OPERATIONS[operation], options or {}
        url, body = self.url(operation, args), args.get("body")
        if spec["body"] == "required" and body is None:
            raise TypeError("%s: body is required" % operation)
        # Serialize once: a retry resends exactly these bytes.
        payload = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"accept": "application/json", "user-agent": self._user_agent}
        if payload is not None:
            headers["content-type"] = "application/json"
        if spec["auth"]:
            if not self._token:
                raise TypeError("%s needs an Agent credential: pass token to ProofTaskClient" % operation)
            headers["authorization"] = "Bearer " + self._token
        replayable = spec["method"] == "GET" or request_id_of(body) is not None
        retries = options.get("max_retries", self._max_retries) if replayable else 0
        timeout = options.get("timeout", self._timeout)
        attempt = 0
        while True:
            request = urllib.request.Request(url, data=payload, headers=headers, method=spec["method"])
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    text = response.read().decode("utf-8")
                try:
                    return json.loads(text) if text else None
                except ValueError as error:
                    raise ProofTaskTransportError(operation, spec["method"] != "GET", error) from error
            except urllib.error.HTTPError as error:
                raw = error.read().decode("utf-8", "replace") if error.fp is not None else ""
                header = error.headers.get("retry-after") if error.headers else None
                retry_after = int(header) if header and header.isdigit() and len(header) <= 6 else None
                if error.code in (429, 503) and attempt < retries and (retry_after or 0) <= 60:
                    time.sleep(retry_after if retry_after is not None else 0.5 * 2 ** attempt)
                    attempt += 1
                    continue
                parsed: Any = raw
                try:
                    parsed = json.loads(raw) if raw else None
                except ValueError:
                    pass
                raise api_error(operation, error.code, parsed, retry_after) from None
            except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as error:
                if attempt < retries:
                    time.sleep(0.5 * 2 ** attempt)
                    attempt += 1
                    continue
                raise ProofTaskTransportError(operation, spec["method"] != "GET", error) from error

    def _pages(self, operation: str, args: Dict[str, Any], options: Optional[Dict[str, Any]]) -> Iterator[Any]:
        first = args.get("after")
        return paginate(lambda after: self._call(operation, {**args, "after": after}, options), first)
