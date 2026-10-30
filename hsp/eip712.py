"""EIP-712 Payment Mandate: the payer's wallet authorization.

The payer signs a typed ``PaymentMandate`` authorizing one payment:
payer -> payee, a token, an exact amount, a nonce and a deadline, bound to
the Cart Mandate by ``cart_hash``. The executor (gateway live, local
executor in the demo) verifies the signature BEFORE moving any funds, and
rejects expired mandates, wrong payers, wrong amounts and replayed nonces.

DOMAIN NOTE (honest): the live gateway's exact EIP-712 domain and type
schema are gateway-side details that only onboarding reveals. The domain
below (``FORTEC HSP Payment Mandate`` v1, verifyingContract = the payment
token) is this demo's own mandate domain, used identically by signer,
verifier and executor, so the authorization model is real even though the
live gateway may name its domain differently. Swap ``DOMAIN_NAME`` /
``verifyingContract`` for the gateway's values the day keys arrive; the
sign/verify code does not change.
"""

from eth_account import Account
from eth_account.messages import encode_typed_data

DOMAIN_NAME = "FORTEC HSP Payment Mandate"
DOMAIN_VERSION = "1"

MANDATE_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "PaymentMandate": [
        {"name": "payer", "type": "address"},
        {"name": "payee", "type": "address"},
        {"name": "token", "type": "address"},
        {"name": "amount", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
        {"name": "cartHash", "type": "bytes32"},
    ],
}


def mandate_domain(chain_id: int, token_address: str) -> dict:
    return {
        "name": DOMAIN_NAME,
        "version": DOMAIN_VERSION,
        "chainId": chain_id,
        "verifyingContract": token_address,
    }


def build_mandate_message(payer: str, payee: str, token: str, amount: int,
                          nonce: int, deadline: int, cart_hash_hex: str) -> dict:
    cart_hash_hex = cart_hash_hex.lower().removeprefix("0x")
    if len(cart_hash_hex) != 64:
        raise ValueError("cart_hash must be 32 bytes hex")
    return {
        "payer": payer,
        "payee": payee,
        "token": token,
        "amount": amount,
        "nonce": nonce,
        "deadline": deadline,
        "cartHash": bytes.fromhex(cart_hash_hex),
    }


def sign_mandate(private_key_bytes: bytes, domain: dict, message: dict) -> bytes:
    typed = {
        "types": MANDATE_TYPES,
        "primaryType": "PaymentMandate",
        "domain": domain,
        "message": message,
    }
    account = Account.from_key(private_key_bytes)
    return account.sign_message(encode_typed_data(full_message=typed)).signature


def verify_mandate(domain: dict, message: dict, signature: bytes,
                   expected_payer: str) -> bool:
    """True only if *signature* recovers to *expected_payer* for this mandate."""
    typed = {
        "types": MANDATE_TYPES,
        "primaryType": "PaymentMandate",
        "domain": domain,
        "message": message,
    }
    try:
        recovered = Account.recover_message(encode_typed_data(full_message=typed),
                                            signature=signature)
    except Exception:
        return False
    return recovered.lower() == expected_payer.lower()
