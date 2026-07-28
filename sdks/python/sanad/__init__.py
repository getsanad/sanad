"""Sanad Python client SDK.

This SDK lets an AI agent authenticate to the Sanad gateway. It mirrors
the Go sidecar ``passport proxy`` (see ``cmd/passport``): first the agent enrolls
to obtain a short-lived workload credential, then it attaches the correct headers
to each MCP request routed through the gateway.

Wire formats match the Go implementation byte-for-byte. All base64 is RFC 4648
URL-safe with NO padding (Go's ``base64.RawURLEncoding``). Cryptography is
Ed25519.

Enrolling is two requests: the agent fetches a single-use nonce from the authority,
then presents attestation evidence that covers both that nonce and the public key it
is enrolling. That binding is what stops an enrollment captured off the wire from
being replayed with somebody else's key.

Typical use::

    from sanad import generate_instance_key, enroll, PassportClient

    key = generate_instance_key()
    result = enroll("https://authority.example.com", "bootstrap-token", key["public_key"])
    client = PassportClient("https://gw.example.com", key["private_key"], result["credential"])
    resp = client.request("my-server", "/mcp", principal_token="<opaque principal token>")
    print(resp.status, resp.body)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "generate_instance_key",
    "public_key_of",
    "proof",
    "bootstrap_evidence",
    "request_nonce",
    "enroll",
    "PassportClient",
    "Response",
    "PassportError",
    "EnrollmentError",
    "HEADER_CREDENTIAL",
    "HEADER_PROOF",
    "HEADER_DELEGATION",
]

# Header names must match the Go constants exactly.
HEADER_CREDENTIAL = "X-Agent-Credential"  # workload/workload.go: HeaderCredential
HEADER_PROOF = "X-Agent-Proof"            # workload/workload.go: HeaderProof
HEADER_DELEGATION = "X-Agent-Delegation"  # delegation/transport.go: HeaderDelegation

_SEED_SIZE = 32
_PUB_SIZE = 32
_PRIV64_SIZE = 64  # seed(32) || public(32), matching Go's ed25519.PrivateKey


class PassportError(Exception):
    """Base class for SDK errors."""


class EnrollmentError(PassportError):
    """Raised when enrollment returns a non-200 status."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"enroll: HTTP {status}: {body.strip()}")


# --- base64url (RFC 4648, no padding) helpers -----------------------------------

def _b64url_encode(b: bytes) -> str:
    """Encode raw bytes as unpadded URL-safe base64 (Go base64.RawURLEncoding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode unpadded URL-safe base64, re-adding padding first."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --- Ed25519 key helpers --------------------------------------------------------

def _load_private(private_key: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a base64url string.

    Accepts either a 32-byte seed or the 64-byte ``seed || public`` form (as the
    Go CLI persists it). The first 32 bytes are used as the seed.
    """
    raw = _b64url_decode(private_key)
    if len(raw) not in (_SEED_SIZE, _PRIV64_SIZE):
        raise PassportError(
            f"instance private key must be {_SEED_SIZE} or {_PRIV64_SIZE} bytes, got {len(raw)}"
        )
    seed = raw[:_SEED_SIZE]
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_raw(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# --- Public key/proof primitives ------------------------------------------------

def generate_instance_key() -> Dict[str, str]:
    """Generate a fresh Ed25519 instance key.

    Returns a dict with:

    - ``private_key``: base64url of the 64-byte ``seed(32) || public(32)`` form,
      interchangeable with the Go ``passport keygen`` key file.
    - ``public_key``: base64url of the 32-byte raw public key.
    """
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw() if hasattr(priv, "private_bytes_raw") else _seed_of(priv)
    pub = _public_raw(priv)
    return {
        "private_key": _b64url_encode(seed + pub),
        "public_key": _b64url_encode(pub),
    }


def _seed_of(priv: Ed25519PrivateKey) -> bytes:
    """Extract the 32-byte seed for cryptography versions lacking private_bytes_raw."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def public_key_of(private_key: str) -> str:
    """Return the base64url public key for a base64url private key (seed or seed||pub)."""
    return _b64url_encode(_public_raw(_load_private(private_key)))


def proof(private_key: str, principal_token: str) -> str:
    """Produce the proof of possession: base64url(Ed25519_sign(priv, utf8(principal_token))).

    Mirrors ``workload.Proof`` in the Go code and binds the instance key to the
    specific short-lived principal token.
    """
    priv = _load_private(private_key)
    sig = priv.sign(principal_token.encode("utf-8"))
    return _b64url_encode(sig)


# --- Enrollment -----------------------------------------------------------------

def bootstrap_evidence(bootstrap_token: str, nonce: bytes, public_key: bytes) -> bytes:
    """Build the attestation evidence a Go ``workload.TokenAttestor`` accepts.

    An HMAC-SHA256, keyed by the bootstrap token, over the authority-issued nonce and
    the public key being enrolled. Mirrors Go's ``workload.BootstrapEvidence``
    byte-for-byte: the MAC input is the canonical JSON Go signs over, with the fields
    in that order and the byte fields in standard (padded) base64, which is how Go's
    ``encoding/json`` renders ``[]byte``.

    The bootstrap token never leaves the process, and the result only enrolls this key
    against this nonce — so an enrollment captured off the wire cannot be replayed with
    somebody else's key.
    """
    msg = json.dumps(
        {
            "ctx": "sanad/bootstrap-evidence/v1",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "pub": base64.b64encode(public_key).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(bootstrap_token.encode("utf-8"), msg, hashlib.sha256).digest()


def _post_json(url: str, payload: Dict[str, Any]) -> str:
    """POST a JSON body and return the response text, raising EnrollmentError on failure."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.getcode()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise EnrollmentError(e.code, body) from None

    if status != 200:
        raise EnrollmentError(status, raw)
    return raw


def request_nonce(authority_url: str) -> bytes:
    """Fetch a single-use enrollment nonce from ``POST {authority_url}/enroll/nonce``.

    Mirrors Go's ``workload.RequestNonce``. The nonce is the RATS freshness challenge
    (carried as EAT ``eat_nonce``): the authority accepts it exactly once, within a
    short window, so an attestation built over it cannot be replayed.

    :raises EnrollmentError: on a non-200 response or an unusable nonce.
    """
    raw = _post_json(authority_url.rstrip("/") + "/enroll/nonce", {})
    nonce = json.loads(raw).get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise EnrollmentError(200, "authority returned an unusable nonce")
    return _b64url_decode(nonce)


def enroll(authority_url: str, bootstrap_token: str, public_key: str) -> Dict[str, Any]:
    """Enroll with the authority and return the issued workload credential.

    Mirrors Go's ``workload.Enroll``, which is two requests:

    1. ``POST {authority_url}/enroll/nonce`` for a single-use challenge, then
    2. ``POST {authority_url}/enroll`` with ``{"nonce": ..., "evidence": ...,
       "public_key": ...}``, where the evidence covers both the nonce and the public
       key (see :func:`bootstrap_evidence`).

    On HTTP 200 the response body is the credential JSON, kept verbatim (its embedded
    signature must not be re-serialized).

    :param authority_url: base URL of the authority service.
    :param bootstrap_token: attestation bootstrap token (opaque string).
    :param public_key: base64url of the 32-byte instance public key.
    :returns: ``{"credential": <raw text>, "agent_id": ..., "not_after": ...}``.
    :raises EnrollmentError: on a non-200 response.
    """
    pub = _b64url_decode(public_key)
    if len(pub) != _PUB_SIZE:
        raise PassportError(f"instance public key must be {_PUB_SIZE} bytes, got {len(pub)}")

    nonce = request_nonce(authority_url)
    raw = _post_json(
        authority_url.rstrip("/") + "/enroll",
        {
            "nonce": _b64url_encode(nonce),
            "evidence": _b64url_encode(bootstrap_evidence(bootstrap_token, nonce, pub)),
            "public_key": public_key,
        },
    )

    # Keep the credential text exactly as received; only parse for convenience fields.
    parsed = json.loads(raw)
    return {
        "credential": raw,
        "agent_id": parsed.get("AgentID"),
        "not_after": parsed.get("NotAfter"),
    }


# --- Client ---------------------------------------------------------------------

@dataclass
class Response:
    """A minimal HTTP response returned by :meth:`PassportClient.request`."""

    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def text(self, encoding: str = "utf-8") -> str:
        """Decode the response body as text."""
        return self.body.decode(encoding, errors="replace")

    def json(self) -> Any:
        """Parse the response body as JSON."""
        return json.loads(self.body.decode("utf-8"))


def _credential_text(credential: Union[str, Dict[str, Any]]) -> str:
    """Accept either the raw credential text or the dict returned by :func:`enroll`."""
    if isinstance(credential, dict):
        text = credential.get("credential")
        if not isinstance(text, str):
            raise PassportError("credential dict must contain a 'credential' text field")
        return text
    if isinstance(credential, str):
        return credential
    raise PassportError("credential must be a string or the dict returned by enroll()")


def _instance_key_str(instance_key: Union[str, Dict[str, Any]]) -> str:
    """Accept either the private key string or the dict from generate_instance_key()."""
    if isinstance(instance_key, dict):
        key = instance_key.get("private_key")
        if not isinstance(key, str):
            raise PassportError("instance_key dict must contain a 'private_key' field")
        return key
    if isinstance(instance_key, str):
        return instance_key
    raise PassportError("instance_key must be a string or the dict from generate_instance_key()")


class PassportClient:
    """Attaches Sanad headers and forwards MCP requests to the gateway.

    This mirrors the ``passport proxy`` sidecar: it injects the principal token,
    the workload credential, a proof of possession, and (optionally) a delegation
    chain onto every request.

    :param gateway_url: base URL of the gateway.
    :param instance_key: base64url private key (seed or seed||pub), or the dict from
        :func:`generate_instance_key`.
    :param credential: the raw credential JSON text, or the dict from :func:`enroll`.
    :param delegation: optional delegation chain JSON text (a string), or ``None``.
    """

    def __init__(
        self,
        gateway_url: str,
        instance_key: Union[str, Dict[str, Any]],
        credential: Union[str, Dict[str, Any]],
        delegation: Optional[str] = None,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self._private_key = _instance_key_str(instance_key)
        # Validate the key early.
        _load_private(self._private_key)
        self._credential_text = _credential_text(credential)
        self._delegation = delegation

    def headers(self, principal_token: str) -> Dict[str, str]:
        """Build the passport headers for a request bound to ``principal_token``."""
        h = {
            "Authorization": "Bearer " + principal_token,
            HEADER_CREDENTIAL: _b64url_encode(self._credential_text.encode("utf-8")),
            HEADER_PROOF: proof(self._private_key, principal_token),
        }
        if self._delegation is not None:
            h[HEADER_DELEGATION] = _b64url_encode(self._delegation.encode("utf-8"))
        return h

    def request(
        self,
        server_id: str,
        path: str,
        principal_token: str,
        method: str = "GET",
        body: Optional[Union[bytes, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Send an authenticated request to ``/servers/{server_id}{path}`` on the gateway.

        :param server_id: id of the protected server registered at the gateway.
        :param path: upstream path, must begin with ``/``.
        :param principal_token: opaque principal bearer token.
        :param method: HTTP method (default ``GET``).
        :param body: request body as bytes or str (str is UTF-8 encoded).
        :param headers: extra headers merged after the passport headers.
        :returns: a :class:`Response`.
        """
        if not path.startswith("/"):
            raise PassportError("path must begin with '/'")

        url = f"{self.gateway_url}/servers/{server_id}{path}"

        all_headers = self.headers(principal_token)
        if headers:
            all_headers.update(headers)

        data: Optional[bytes] = None
        if body is not None:
            data = body.encode("utf-8") if isinstance(body, str) else body

        req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
        try:
            with urllib.request.urlopen(req) as resp:
                return Response(
                    status=resp.getcode(),
                    headers=dict(resp.headers.items()),
                    body=resp.read(),
                )
        except urllib.error.HTTPError as e:
            # A non-2xx status is returned as a Response rather than raised.
            return Response(
                status=e.code,
                headers=dict(e.headers.items()) if e.headers else {},
                body=e.read(),
            )
