"""FORTEC — HashKey HSP (Agent Payments & A2A Settlement) entry.

Two agents plus a Python integration for the HashKey Merchant gateway (HSP):

* Receiving agent: publishes payment conditions for a service.
* Payment agent: builds a Payment Mandate from those conditions, signs it
  with the payer wallet (EIP-712), verifies it, and executes settlement.
* Gateway client: Cart Mandate (canonical JSON -> SHA-256 -> ES256K JWT),
  HMAC-SHA256 signed order/payment calls, state-machine tracking and
  signed webhooks, following the HSP flow researched 2026-10-29.

TESTNET ONLY. No mainnet code path is ever constructed here: the default
chain configuration is HSK testnet (chain ID 133) and the local demo chain.
See README.md "Honest limits" before claiming anything about this entry.
"""

from .canonical import canonical_json
from .state_machine import PaymentState, PaymentTracker

__all__ = ["canonical_json", "PaymentState", "PaymentTracker"]
