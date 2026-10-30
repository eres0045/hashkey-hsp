"""Unit tests: canonical JSON, ES256K JWT, HMAC headers, mandates, states."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_account import Account

from hsp.canonical import canonical_dumps
from hsp.hmac_client import body_hash, build_headers, sign_message
from hsp.jwt_es256k import build_merchant_authorization, sign_jwt, verify_jwt
from hsp.mandate import build_cart_contents, cart_hash
from hsp.state_machine import IllegalTransition, PaymentState, PaymentTracker

MERCHANT_KEY = bytes.fromhex("11" * 32)
MERCHANT = Account.from_key(MERCHANT_KEY)


class TestCanonical(unittest.TestCase):
    def test_key_sorting_and_compactness(self):
        self.assertEqual(
            canonical_dumps({"b": 1, "a": {"d": 4, "c": 3}}),
            '{"a":{"c":3,"d":4},"b":1}',
        )

    def test_string_escaping(self):
        self.assertEqual(canonical_dumps('a"b\\c\n'), '"a\\"b\\\\c\\n"')
        self.assertEqual(canonical_dumps("café"), '"café"')  # UTF-8, not \u

    def test_rfc8785_example_shape(self):
        # Object key order must not depend on insertion order.
        a = canonical_dumps({"z": [1, {"b": 2, "a": 1}], "m": None})
        b = canonical_dumps({"m": None, "z": [1, {"a": 1, "b": 2}]})
        self.assertEqual(a, b)


class TestJwt(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        claims = {"sub": "FORTEC", "aud": "HashkeyMerchant", "cart_hash": "ab" * 32}
        token = sign_jwt(MERCHANT_KEY, claims)
        out, address = verify_jwt(token, expected_address=MERCHANT.address)
        self.assertEqual(out["sub"], "FORTEC")
        self.assertEqual(address.lower(), MERCHANT.address.lower())

    def test_tampered_payload_rejected(self):
        token = sign_jwt(MERCHANT_KEY, {"sub": "FORTEC"})
        head, body, sig = token.split(".")
        import base64

        def b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        tampered = head + "." + b64(b'{"sub":"EVIL"}') + "." + sig
        with self.assertRaises(ValueError):
            verify_jwt(tampered, expected_address=MERCHANT.address)

    def test_merchant_authorization_claims(self):
        import time as _time

        token = build_merchant_authorization(MERCHANT_KEY, "FORTEC", "cd" * 32,
                                             ttl_seconds=3600,
                                             now=int(_time.time()))
        claims, _ = verify_jwt(token)
        self.assertEqual(claims["aud"], "HashkeyMerchant")
        self.assertEqual(claims["sub"], "FORTEC")
        self.assertEqual(claims["cart_hash"], "cd" * 32)
        self.assertEqual(claims["exp"] - claims["iat"], 3600)


class TestHmac(unittest.TestCase):
    def test_message_layout_and_headers(self):
        body = b'{"a":1}'
        sig = sign_message("secret", "POST", "/api/v1/merchant/orders", "",
                           body, "1700000000", "nonce1")
        expected_message = "\n".join(["POST", "/api/v1/merchant/orders", "",
                                      hashlib.sha256(body).hexdigest(),
                                      "1700000000", "nonce1"])
        import hashlib as _h
        import hmac as _m

        self.assertEqual(
            sig, _m.new(b"secret", expected_message.encode(),
                        _h.sha256).hexdigest())
        headers = build_headers("key", "secret", "POST",
                                "/api/v1/merchant/orders", body=body,
                                timestamp="1700000000", nonce="nonce1")
        self.assertEqual(headers["X-App-Key"], "key")
        self.assertEqual(headers["X-Signature"], sig)
        self.assertEqual(body_hash(b""), hashlib.sha256(b"").hexdigest())


class TestMandate(unittest.TestCase):
    def test_contents_fields_and_hash_stability(self):
        contents = build_cart_contents(
            merchant_name="FORTEC", cart_mandate_id="cart-1",
            payment_request_id="pay-1", pay_to="0x" + "22" * 20, coin="USDC",
            contract_address="0x" + "33" * 20, network="hsk-testnet",
            chain_id=133, total_value="10.00")
        self.assertEqual(contents["id"], "cart-1")
        method = contents["payment_request"]["method_data"][0]
        self.assertEqual(method["supported_methods"], "https://www.x402.org/")
        self.assertEqual(method["data"]["x402Version"], 2)
        self.assertEqual(method["data"]["chain_id"], 133)
        self.assertEqual(
            contents["payment_request"]["details"]["total"],
            {"currency": "USD", "value": "10.00"})
        from hsp.canonical import canonical_json

        self.assertEqual(cart_hash(contents),
                         hashlib.sha256(canonical_json(contents)).hexdigest())

    def test_cart_hash_changes_with_amount(self):
        base = dict(merchant_name="FORTEC", cart_mandate_id="c",
                    payment_request_id="p", pay_to="0x" + "22" * 20,
                    coin="USDC", contract_address="0x" + "33" * 20,
                    network="hsk-testnet", chain_id=133)
        a = cart_hash(build_cart_contents(total_value="10.00", **base))
        b = cart_hash(build_cart_contents(total_value="10.01", **base))
        self.assertNotEqual(a, b)


class TestStateMachine(unittest.TestCase):
    def test_full_legal_path(self):
        tracker = PaymentTracker("flow-1")
        for state in [PaymentState.SUBMITTED, PaymentState.VERIFIED,
                      PaymentState.PROCESSING, PaymentState.INCLUDED,
                      PaymentState.SAFE, PaymentState.FINALIZED]:
            tracker.advance(state)
        self.assertTrue(tracker.is_terminal)
        self.assertEqual(tracker.state, PaymentState.FINALIZED)

    def test_illegal_skip_rejected(self):
        tracker = PaymentTracker("flow-2")
        with self.assertRaises(IllegalTransition):
            tracker.advance(PaymentState.FINALIZED)

    def test_fail_from_any_live_state(self):
        tracker = PaymentTracker("flow-3")
        tracker.advance(PaymentState.SUBMITTED)
        tracker.fail("gateway rejected")
        self.assertEqual(tracker.state, PaymentState.FAILED)
        self.assertTrue(tracker.is_terminal)


if __name__ == "__main__":
    unittest.main()
