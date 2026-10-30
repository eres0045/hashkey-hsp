"""HSP payment state machine.

States per the researched HSP flow::

    payment-required -> submitted -> verified -> processing
    -> included -> safe -> finalized
    failed (terminal, reachable from any non-terminal state)

The gateway emits webhooks at ``included``/``safe``/``finalized``/``failed``
(or the client polls ``GET /merchant/payments``); this tracker is the
single place that enforces legal transitions so a demo can never show a
payment jumping backwards or skipping to ``finalized`` without inclusion.
"""

from datetime import datetime, timezone


class PaymentState:
    PAYMENT_REQUIRED = "payment-required"
    SUBMITTED = "submitted"
    VERIFIED = "verified"
    PROCESSING = "processing"
    INCLUDED = "included"
    SAFE = "safe"
    FINALIZED = "finalized"
    FAILED = "failed"

    TERMINAL = frozenset({FINALIZED, FAILED})


_ALLOWED = {
    PaymentState.PAYMENT_REQUIRED: {PaymentState.SUBMITTED, PaymentState.FAILED},
    PaymentState.SUBMITTED: {PaymentState.VERIFIED, PaymentState.FAILED},
    PaymentState.VERIFIED: {PaymentState.PROCESSING, PaymentState.FAILED},
    PaymentState.PROCESSING: {PaymentState.INCLUDED, PaymentState.FAILED},
    PaymentState.INCLUDED: {PaymentState.SAFE, PaymentState.FAILED},
    PaymentState.SAFE: {PaymentState.FINALIZED, PaymentState.FAILED},
    PaymentState.FINALIZED: set(),
    PaymentState.FAILED: set(),
}


class IllegalTransition(ValueError):
    pass


class PaymentTracker:
    """Tracks one payment flow through the HSP state machine."""

    def __init__(self, flow_id: str):
        self.flow_id = flow_id
        self.state = PaymentState.PAYMENT_REQUIRED
        self.history = [(self.state, self._now(), "flow created")]
        self.tx_hash: str | None = None
        self.failure_reason: str | None = None

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def advance(self, new_state: str, detail: str = "", tx_hash: str | None = None):
        if new_state not in _ALLOWED[self.state]:
            raise IllegalTransition(f"{self.state} -> {new_state} is not allowed")
        self.state = new_state
        if tx_hash:
            self.tx_hash = tx_hash
        self.history.append((new_state, self._now(), detail))
        return self.state

    def fail(self, reason: str):
        if self.state in PaymentState.TERMINAL:
            raise IllegalTransition(f"cannot fail terminal state {self.state}")
        self.failure_reason = reason
        self.state = PaymentState.FAILED
        self.history.append((PaymentState.FAILED, self._now(), reason))
        return self.state

    @property
    def is_terminal(self) -> bool:
        return self.state in PaymentState.TERMINAL

    def as_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "state": self.state,
            "tx_hash": self.tx_hash,
            "failure_reason": self.failure_reason,
            "history": [
                {"state": s, "at": t, "detail": d} for s, t, d in self.history
            ],
        }
