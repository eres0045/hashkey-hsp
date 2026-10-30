"""Local gateway stand-in (CLEARLY LABELLED — not the live HSP gateway).

Until merchant onboarding issues an app_key/app_secret, there is no live
gateway to call. This stand-in implements the same surface the demo
needs — order creation, ``pay-mandate`` submission, flow polling — plus
signed webhook delivery, so the agent code is exercised end to end and
plugs into :class:`hsp.gateway_client.GatewayClient` the moment real
credentials arrive (swap the base URL; the client code is unchanged).

What it does NOT do: it never claims to be HashKey's gateway, never
broadcasts via EIP-3009/Permit2 (the live gateway's job), and never
touches mainnet. Settlement here is the :class:`hsp.executor.LocalExecutor`
transferFrom path, labelled as such in every response.
"""

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import eip712
from .state_machine import PaymentState, PaymentTracker
from .webhook import compute_webhook_signature


class StandinGateway:
    """In-memory gateway stand-in with optional executor + webhooks."""

    def __init__(self, executor=None, webhook_url=None, webhook_secret=""):
        self.executor = executor
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.orders: dict[str, dict] = {}
        self.flows: dict[str, PaymentTracker] = {}

    def create_order(self, contents: dict, merchant_authorization: str) -> dict:
        order_id = "order-" + uuid.uuid4().hex[:12]
        flow_id = "flow-" + uuid.uuid4().hex[:12]
        self.orders[order_id] = {
            "order_id": order_id,
            "flow_id": flow_id,
            "contents": contents,
            "merchant_authorization": merchant_authorization,
            "gateway": "standin (NOT live HSP gateway)",
        }
        self.flows[flow_id] = PaymentTracker(flow_id)
        return {
            "order_id": order_id,
            "flow_id": flow_id,
            "state": PaymentState.PAYMENT_REQUIRED,
            "payment_url": f"standin://pay/{flow_id}",
            "gateway": "standin (NOT live HSP gateway)",
        }

    def pay_mandate(self, domain: dict, message: dict, signature: bytes,
                    flow_id: str) -> dict:
        tracker = self.flows.get(flow_id)
        if tracker is None:
            raise KeyError(f"unknown flow {flow_id}")
        if self.executor is None:
            # No executor wired: mandate is verified, settlement pending.
            if not eip712.verify_mandate(domain, message, signature,
                                         message["payer"]):
                tracker.fail("mandate signature does not recover to payer")
                raise ValueError("mandate signature verification failed")
            tracker.advance(PaymentState.SUBMITTED, "mandate received (standin)")
            tracker.advance(PaymentState.VERIFIED, "mandate verified (standin)")
            return tracker.as_dict()
        receipt = self.executor.settle(domain, message, signature, tracker)
        self._emit_webhooks(tracker)
        return {**tracker.as_dict(), "receipt": _receipt_summary(receipt)}

    def get_flow(self, flow_id: str) -> dict:
        tracker = self.flows.get(flow_id)
        if tracker is None:
            raise KeyError(f"unknown flow {flow_id}")
        return tracker.as_dict()

    def list_payments(self) -> list[dict]:
        return [t.as_dict() for t in self.flows.values()]

    def _emit_webhooks(self, tracker: PaymentTracker):
        if not self.webhook_url:
            return
        import urllib.request

        for state, at, detail in tracker.history:
            if state not in (PaymentState.INCLUDED, PaymentState.SAFE,
                             PaymentState.FINALIZED, PaymentState.FAILED):
                continue
            payload = json.dumps({
                "flow_id": tracker.flow_id, "state": state,
                "tx_hash": tracker.tx_hash, "detail": detail, "at": at,
            }).encode()
            import time

            stamp = str(int(time.time()))
            header = f"t={stamp},v1=" + compute_webhook_signature(
                self.webhook_secret, stamp, payload)
            request = urllib.request.Request(
                self.webhook_url, data=payload,
                headers={"Content-Type": "application/json",
                         "X-Signature": header}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    response.read()
            except Exception:
                pass  # gateway retries; standin does not block on webhooks


def _receipt_summary(receipt: dict) -> dict:
    return {
        "transactionHash": receipt.get("transactionHash"),
        "blockNumber": receipt.get("blockNumber"),
        "status": receipt.get("status"),
    }


def make_standin_handler(gateway: StandinGateway):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw) if raw else {}

        def do_POST(self):  # noqa: N802
            try:
                body = self._read_json()
            except ValueError:
                self._send(400, {"error": "bad json"})
                return
            if self.path == "/api/v1/merchant/orders":
                result = gateway.create_order(
                    body.get("contents", {}),
                    body.get("merchant_authorization", ""))
                self._send(200, result)
            elif self.path == "/api/v1/payment/pay-mandate":
                try:
                    domain = body["domain"]
                    message = body["message"]
                    # cartHash arrives as hex in JSON; restore bytes.
                    message = dict(message)
                    cart = message.get("cartHash", "")
                    if isinstance(cart, str):
                        message["cartHash"] = bytes.fromhex(
                            cart.removeprefix("0x"))
                    signature = bytes.fromhex(
                        body["signature"].removeprefix("0x"))
                    result = gateway.pay_mandate(domain, message, signature,
                                                 body["flow_id"])
                except (KeyError, ValueError) as exc:
                    self._send(400, {"error": str(exc)})
                    return
                self._send(200, result)
            else:
                self._send(404, {"error": "unknown path"})

        def do_GET(self):  # noqa: N802
            if self.path.startswith("/api/v1/payment/flow/"):
                flow_id = self.path.rsplit("/", 1)[-1]
                try:
                    self._send(200, gateway.get_flow(flow_id))
                except KeyError:
                    self._send(404, {"error": "unknown flow"})
            elif self.path == "/merchant/payments":
                self._send(200, {"payments": gateway.list_payments()})
            else:
                self._send(404, {"error": "unknown path"})

        def log_message(self, *args):
            pass

    return Handler


def serve_standin(gateway: StandinGateway, host: str = "127.0.0.1",
                  port: int = 0):
    """Start the stand-in server on a thread; return (server, base_url)."""
    server = ThreadingHTTPServer(
        (host, port), make_standin_handler(gateway))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_port = server.server_address[1]
    return server, f"http://{host}:{actual_port}"
