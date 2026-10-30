"""HSP gateway HTTP client (merchant API + payment flow API).

Hosts (researched 2026-10-29):
  QA (testnet sandbox)  https://merchant-qa.hashkeymerchant.com
  Staging (mainnet tok.) https://merchant-stg.hashkeymerchant.com
  Production             https://hsp.hashkey.com

Endpoints (researched flow; re-confirm paths against live docs at
onboarding — the client takes ``base_url`` so no host is hard-coded):
  POST /api/v1/merchant/orders
  POST /merchant/orders/reusable
  GET  /merchant/payments
  GET  /merchant/payments/reusable
  POST /api/v1/payment/pay-mandate
  GET  /api/v1/payment/flow/:id

No live gateway call is made anywhere in this project without an
``app_key``/``app_secret`` issued by merchant onboarding. Until onboarding
completes, :mod:`hsp.standin` provides the same surface locally.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from .hmac_client import build_headers

HOSTS = {
    "qa": "https://merchant-qa.hashkeymerchant.com",
    "staging": "https://merchant-stg.hashkeymerchant.com",
    "production": "https://hsp.hashkey.com",
}


class GatewayError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"gateway HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class GatewayClient:
    def __init__(self, base_url: str, app_key: str, app_secret: str,
                 timeout: int = 30, opener=None):
        self.base_url = base_url.rstrip("/")
        self.app_key = app_key
        self.app_secret = app_secret
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener()

    def _request(self, method: str, path: str, query: dict | None = None,
                 body: dict | None = None):
        query_str = urllib.parse.urlencode(query or {})
        body_bytes = (
            json.dumps(body, separators=(",", ":")).encode()
            if body is not None
            else b""
        )
        headers = build_headers(
            self.app_key, self.app_secret, method, path, query_str, body_bytes
        )
        url = self.base_url + path
        if query_str:
            url += "?" + query_str
        request = urllib.request.Request(url, data=body_bytes or None,
                                         headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise GatewayError(exc.code, exc.read().decode(errors="replace")) from exc
        return json.loads(raw) if raw else {}

    def create_order(self, body: dict):
        return self._request("POST", "/api/v1/merchant/orders", body=body)

    def create_reusable_order(self, body: dict):
        return self._request("POST", "/merchant/orders/reusable", body=body)

    def get_payment(self, query: dict | None = None):
        return self._request("GET", "/merchant/payments", query=query)

    def get_reusable_payment(self, query: dict | None = None):
        return self._request("GET", "/merchant/payments/reusable", query=query)

    def pay_mandate(self, body: dict):
        return self._request("POST", "/api/v1/payment/pay-mandate", body=body)

    def get_flow(self, flow_id: str):
        return self._request("GET", f"/api/v1/payment/flow/{flow_id}")
