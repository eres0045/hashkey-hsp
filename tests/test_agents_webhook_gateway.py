"""Unit tests: agents/EIP-712, webhook receiver, gateway client surface."""

import io
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_account import Account

from hsp import eip712
from hsp.agents import PaymentAgent, PaymentConditions, ReceivingAgent
from hsp.gateway_client import GatewayClient
from hsp.webhook import WebhookReceiver, compute_webhook_signature

PAYER_KEY = bytes.fromhex("22" * 32)
MERCHANT_KEY = bytes.fromhex("33" * 32)
TOKEN = "0x" + "44" * 20
PAYEE = "0x" + "55" * 20


def conditions() -> PaymentConditions:
    return PaymentConditions(
        service_name="API credits", pay_to=PAYEE, coin="USDC",
        token_address=TOKEN, network="hsk-testnet", chain_id=133,
        total_value="25.50", token_decimals=6)


class TestAgents(unittest.TestCase):
    def test_amount_conversion_exact(self):
        self.assertEqual(conditions().amount_smallest_unit(), 25_500_000)
        bad = PaymentConditions(service_name="x", pay_to=PAYEE, coin="USDC",
                                token_address=TOKEN, network="hsk-testnet",
                                chain_id=133, total_value="0.0000001",
                                token_decimals=6)
        with self.assertRaises(ValueError):
            bad.amount_smallest_unit()

    def test_mandate_sign_verify_and_tamper(self):
        receiving = ReceivingAgent("FORTEC", PAYEE, MERCHANT_KEY)
        payer = PaymentAgent(PAYER_KEY)
        contents, digest, jwt = receiving.build_cart(conditions(), "cart-9", "pay-9")
        self.assertEqual(len(digest), 64)
        self.assertEqual(jwt.count("."), 2)
        domain, message = payer.build_mandate(conditions(), digest, nonce=7,
                                              deadline=2_000_000_000)
        signature = payer.sign_mandate(domain, message)
        self.assertTrue(payer.verify_mandate(domain, message, signature))
        self.assertTrue(eip712.verify_mandate(domain, message, signature,
                                              payer.address))
        tampered = dict(message, amount=message["amount"] + 1)
        self.assertFalse(eip712.verify_mandate(domain, tampered, signature,
                                               payer.address))

    def test_wrong_payer_rejected(self):
        payer = PaymentAgent(PAYER_KEY)
        domain, message = payer.build_mandate(conditions(), "ab" * 32, nonce=1,
                                              deadline=2_000_000_000)
        signature = payer.sign_mandate(domain, message)
        other = Account.from_key(bytes.fromhex("66" * 32)).address
        self.assertFalse(eip712.verify_mandate(domain, message, signature, other))


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, payload: dict):
        self.payload = payload
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        return FakeResponse(self.payload)


class TestGatewayClient(unittest.TestCase):
    def test_request_shape_and_auth_headers(self):
        opener = FakeOpener({"ok": True})
        client = GatewayClient("https://merchant-qa.hashkeymerchant.com",
                               "app-key", "app-secret", opener=opener)
        result = client.create_order({"contents": {"id": "c1"}})
        self.assertEqual(result, {"ok": True})
        request = opener.requests[0]
        self.assertTrue(request.full_url.endswith("/api/v1/merchant/orders"))
        self.assertEqual(request.headers["X-app-key"], "app-key")
        self.assertIn("x-signature", [k.lower() for k in request.headers])
        body = json.loads(request.data)
        self.assertEqual(body["contents"]["id"], "c1")

    def test_flow_path(self):
        opener = FakeOpener({"state": "included"})
        client = GatewayClient("https://merchant-qa.hashkeymerchant.com",
                               "k", "s", opener=opener)
        client.get_flow("flow-abc")
        self.assertTrue(opener.requests[0].full_url.endswith(
            "/api/v1/payment/flow/flow-abc"))


class TestWebhook(unittest.TestCase):
    def test_verified_event_accepted_unsigned_rejected(self):
        receiver = WebhookReceiver("whsec-test")
        payload = json.dumps({"flow_id": "f1", "state": "included"}).encode()
        stamp = str(int(time.time()))
        header = f"t={stamp},v1=" + compute_webhook_signature(
            "whsec-test", stamp, payload)
        status, _ = receiver.handle(payload, header)
        self.assertEqual(status, 200)
        self.assertEqual(len(receiver.events), 1)
        status, _ = receiver.handle(payload, "t=1,v1=deadbeef")
        self.assertEqual(status, 400)
        status, _ = receiver.handle(payload, header.replace("v1=", "v1=00"))
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
