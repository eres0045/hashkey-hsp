"""The two agents: receiving agent and payment agent.

Receiving agent (the merchant / service side, team FORTEC):
  sets the payment conditions — what is being sold, for how much, in
  which coin, to which wallet, and until when — and turns them into a
  Cart Mandate.

Payment agent (the payer side):
  takes those conditions, builds the Payment Mandate, signs it with the
  payer wallet, verifies its own signature, and hands it to an executor
  (the live HSP gateway once onboarded; the local executor in the demo).

Amounts: the Cart Mandate total is a decimal string (``"10.00"``); the
on-chain mandate amount is the token's smallest unit (integer). The
conversion uses the token's decimals and is exact — no floats.
"""

from dataclasses import dataclass
from decimal import Decimal

from eth_account import Account

from . import eip712
from .mandate import build_cart_contents, build_merchant_authorization_for_cart


@dataclass
class PaymentConditions:
    service_name: str
    pay_to: str
    coin: str
    token_address: str
    network: str
    chain_id: int
    total_value: str  # decimal string, e.g. "10.00"
    token_decimals: int = 6
    currency: str = "USD"

    def amount_smallest_unit(self) -> int:
        """Exact decimal-string -> smallest-unit conversion (no floats)."""
        value = Decimal(self.total_value)
        scaled = value * (Decimal(10) ** self.token_decimals)
        if scaled != int(scaled):
            raise ValueError(f"{self.total_value} has more decimals than the token allows")
        return int(scaled)


class ReceivingAgent:
    """The service side: publishes conditions, builds Cart Mandates."""

    def __init__(self, merchant_name: str, wallet_address: str,
                 merchant_private_key: bytes):
        self.merchant_name = merchant_name
        self.wallet_address = wallet_address
        self.merchant_private_key = merchant_private_key

    def build_cart(self, conditions: PaymentConditions, cart_mandate_id: str,
                   payment_request_id: str):
        """Return ``(contents, cart_hash, merchant_authorization_jwt)``."""
        contents = build_cart_contents(
            merchant_name=self.merchant_name,
            cart_mandate_id=cart_mandate_id,
            payment_request_id=payment_request_id,
            pay_to=conditions.pay_to,
            coin=conditions.coin,
            contract_address=conditions.token_address,
            network=conditions.network,
            chain_id=conditions.chain_id,
            total_value=conditions.total_value,
            currency=conditions.currency,
        )
        token, digest = build_merchant_authorization_for_cart(
            self.merchant_private_key, self.merchant_name, contents
        )
        return contents, digest, token


class PaymentAgent:
    """The payer side: signs and verifies the Payment Mandate."""

    def __init__(self, payer_private_key: bytes):
        self.account = Account.from_key(payer_private_key)

    @property
    def address(self) -> str:
        return self.account.address

    def build_mandate(self, conditions: PaymentConditions, cart_hash: str,
                      nonce: int, deadline: int):
        domain = eip712.mandate_domain(conditions.chain_id,
                                       conditions.token_address)
        message = eip712.build_mandate_message(
            payer=self.address,
            payee=conditions.pay_to,
            token=conditions.token_address,
            amount=conditions.amount_smallest_unit(),
            nonce=nonce,
            deadline=deadline,
            cart_hash_hex=cart_hash,
        )
        return domain, message

    def sign_mandate(self, domain: dict, message: dict) -> bytes:
        return eip712.sign_mandate(self.account.key, domain, message)

    def verify_mandate(self, domain: dict, message: dict, signature: bytes) -> bool:
        return eip712.verify_mandate(domain, message, signature, self.address)
