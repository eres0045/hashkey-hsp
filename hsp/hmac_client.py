"""HMAC-SHA256 request signing for HSP merchant API calls.

Header set per the researched HSP flow: ``X-App-Key``, ``X-Signature``,
``X-Timestamp``, ``X-Nonce``. The signed message is::

    {METHOD}\\n{PATH}\\n{QUERY}\\n{bodyHash}\\n{timestamp}\\n{nonce}

where ``bodyHash`` is the lowercase hex SHA-256 of the request body
(empty body -> SHA-256 of the empty string).

ASSUMPTION, flagged for onboarding confirmation: the researched flow
specifies the message layout but the gateway docs (JS-rendered, not
machine-readable from this VM) could not be re-read to confirm whether
``bodyHash`` is hex or base64. Hex is implemented; if the live gateway
rejects signatures, flip ``body_hash`` to base64 and re-run the unit test
``test_hmac_client.py::test_known_vector`` against a gateway-issued vector.
"""

import hashlib
import hmac
import secrets


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign_message(secret: str, method: str, path: str, query: str,
                 body: bytes, timestamp: str, nonce: str) -> str:
    message = "\n".join(
        [method.upper(), path, query, body_hash(body), timestamp, nonce]
    )
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def build_headers(app_key: str, app_secret: str, method: str, path: str,
                  query: str = "", body: bytes = b"",
                  timestamp: str | None = None, nonce: str | None = None) -> dict:
    """Build the HSP authentication headers for one request."""
    import time

    timestamp = timestamp if timestamp is not None else str(int(time.time()))
    nonce = nonce if nonce is not None else secrets.token_hex(16)
    signature = sign_message(app_secret, method, path, query, body, timestamp, nonce)
    return {
        "X-App-Key": app_key,
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Content-Type": "application/json",
    }
