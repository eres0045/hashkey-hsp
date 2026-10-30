"""Signed webhook verification and receiver (HSP).

The gateway signs webhooks with header::

    X-Signature: t=<unix timestamp>,v1=<hex HMAC-SHA256>

where ``v1`` is HMAC-SHA256 (webhook secret) over ``"<t>.<raw body>"``.
The receiver must respond 2xx within 10 seconds; the gateway retries on
1m / 5m / 15m / 1h / 6h / 24h if it does not.

ASSUMPTION, flagged for onboarding confirmation: the researched flow
names the header format (``t=...,v1=...``) but the exact signed payload
(``t.payload``) is the standard construction for this header shape; it
must be confirmed against the live gateway docs when keys arrive. The
receiver therefore verifies strictly and rejects anything unsigned or
stale (>5 minutes old) rather than accepting optimistically.
"""

import hashlib
import hmac
import json
import time
from http.server import BaseHTTPRequestHandler


def parse_signature_header(header: str) -> tuple[str, str]:
    parts = dict(item.split("=", 1) for item in header.split(",") if "=" in item)
    if "t" not in parts or "v1" not in parts:
        raise ValueError("X-Signature header must carry t= and v1=")
    return parts["t"], parts["v1"]


def compute_webhook_signature(secret: str, timestamp: str, payload: bytes) -> str:
    message = f"{timestamp}.".encode() + payload
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def verify_webhook_signature(payload: bytes, header: str, secret: str,
                             tolerance_seconds: int = 300) -> bool:
    """Verify a webhook payload against its X-Signature header."""
    try:
        timestamp, v1 = parse_signature_header(header)
    except ValueError:
        return False
    try:
        age = abs(time.time() - int(timestamp))
    except ValueError:
        return False
    if age > tolerance_seconds:
        return False
    expected = compute_webhook_signature(secret, timestamp, payload)
    return hmac.compare_digest(expected, v1)


class WebhookReceiver:
    """Records verified webhook events; rejects everything else."""

    def __init__(self, secret: str):
        self.secret = secret
        self.events: list[dict] = []
        self.rejected: int = 0

    def handle(self, payload: bytes, signature_header: str) -> tuple[int, str]:
        """Return ``(http_status, message)``; 200 only for verified events."""
        if not verify_webhook_signature(payload, signature_header, self.secret):
            self.rejected += 1
            return 400, "bad signature"
        try:
            event = json.loads(payload)
        except ValueError:
            self.rejected += 1
            return 400, "bad json"
        self.events.append(event)
        return 200, "ok"


def make_webhook_handler(receiver: WebhookReceiver):
    """Build a BaseHTTPRequestHandler subclass serving *receiver* at /webhook."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler naming
            if self.path != "/webhook":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            status, message = receiver.handle(
                payload, self.headers.get("X-Signature", "")
            )
            body = message.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence default logging
            pass

    return Handler
