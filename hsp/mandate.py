"""Cart Mandate construction (HSP / AP2-aligned).

A Cart Mandate binds one checkout: the merchant's cart contents are
canonicalized (RFC 8785), hashed (SHA-256 -> ``cart_hash``), and the hash
is carried in the ES256K ``merchant_authorization`` JWT. The gateway
returns a payment URL / order for the payer; the payer's wallet then signs
an EIP-712 authorization (the Payment Mandate, see :mod:`hsp.eip712`).

Field layout follows the HSP flow researched 2026-10-29. One honest
caveat: the live gateway docs are JS-rendered and could not be re-read
from this VM, so the exact nesting of ``payment_request``/``details``
inside ``contents`` must be re-confirmed against the gateway schema at
onboarding. Every field the researched flow names is present; nothing
else is invented.
"""

import hashlib
from datetime import datetime, timedelta, timezone

from .canonical import canonical_json
from .jwt_es256k import build_merchant_authorization

X402_SUPPORTED_METHOD = "https://www.x402.org/"


def rfc3339(dt: datetime) -> str:
    """Format a datetime as RFC 3339 UTC (``...Z``)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_cart_contents(
    merchant_name: str,
    cart_mandate_id: str,
    payment_request_id: str,
    pay_to: str,
    coin: str,
    contract_address: str,
    network: str,
    chain_id: int,
    total_value: str,
    currency: str = "USD",
    cart_expiry: str | None = None,
    user_cart_confirmation_required: bool = False,
) -> dict:
    """Build the Cart Mandate ``contents`` object.

    ``total_value`` is a decimal string (e.g. ``"10.00"``), never a float,
    so the canonical hash is exact. ``cart_expiry`` defaults to ~2 hours
    from now (one-time mandate window per the researched flow).
    """
    if cart_expiry is None:
        cart_expiry = rfc3339(datetime.now(timezone.utc) + timedelta(hours=2))
    return {
        "id": cart_mandate_id,
        "user_cart_confirmation_required": user_cart_confirmation_required,
        "payment_request": {
            "method_data": [
                {
                    "supported_methods": X402_SUPPORTED_METHOD,
                    "data": {
                        "x402Version": 2,
                        "network": network,
                        "chain_id": chain_id,
                        "contract_address": contract_address,
                        "pay_to": pay_to,
                        "coin": coin,
                    },
                }
            ],
            "details": {
                "id": payment_request_id,
                "total": {"currency": currency, "value": total_value},
            },
        },
        "cart_expiry": cart_expiry,
        "merchant_name": merchant_name,
    }


def cart_hash(contents: dict) -> str:
    """SHA-256 (hex) of the canonical JSON of the cart contents."""
    return hashlib.sha256(canonical_json(contents)).hexdigest()


def build_merchant_authorization_for_cart(
    merchant_private_key: bytes,
    merchant_name: str,
    contents: dict,
    ttl_seconds: int = 7200,
) -> tuple[str, str]:
    """Return ``(merchant_authorization_jwt, cart_hash)`` for *contents*."""
    digest = cart_hash(contents)
    token = build_merchant_authorization(
        merchant_private_key, merchant_name, digest, ttl_seconds=ttl_seconds
    )
    return token, digest
