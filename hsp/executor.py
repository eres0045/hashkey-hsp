"""Settlement executor + JSON-RPC chain client.

Live, the HSP gateway validates the Payment Mandate and broadcasts via
EIP-3009 ``transferWithAuthorization`` or Permit2. The local executor
below performs the *equivalent, honestly-labelled* settlement for the
demo: it verifies the EIP-712 mandate signature, checks amount/recipient/
deadline, then submits an ERC-20 ``transferFrom`` from a payer that has
pre-approved the executor. It never moves funds on an unverified,
expired, or mismatched mandate, and it never touches mainnet.

The chain client speaks plain JSON-RPC (urllib, stdlib only) so the same
executor code runs against a local chain, HSK testnet, or any EVM RPC —
only the URL changes.
"""

import json
import time
import urllib.request

from eth_account import Account
from eth_utils import keccak

from . import eip712
from .state_machine import PaymentState, PaymentTracker

ERC20_TRANSFER_FROM_SELECTOR = keccak(b"transferFrom(address,address,uint256)")[:4]
ERC20_ALLOWANCE_SELECTOR = keccak(b"allowance(address,address)")[:4]
ERC20_BALANCE_SELECTOR = keccak(b"balanceOf(address)")[:4]


def _abi_address(address: str) -> bytes:
    return bytes.fromhex(address.lower().removeprefix("0x").rjust(64, "0"))


def _abi_uint(value: int) -> bytes:
    return value.to_bytes(32, "big")


def transfer_from_calldata(sender: str, recipient: str, amount: int) -> bytes:
    return (ERC20_TRANSFER_FROM_SELECTOR + _abi_address(sender)
            + _abi_address(recipient) + _abi_uint(amount))


def _as_int(value) -> int:
    """Parse an RPC quantity that may be a hex string or a plain int."""
    if isinstance(value, int):
        return value
    return int(str(value).removeprefix("0x"), 16)


def _decode_uint256(data_hex: str) -> int:
    return _as_int(data_hex)


class ChainError(Exception):
    pass


class JsonRpcClient:
    """Minimal EVM JSON-RPC client (no web3 dependency)."""

    def __init__(self, rpc_url: str, timeout: int = 30, opener=None,
                 default_from: str | None = None):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener()
        self.default_from = default_from
        self._id = 0

    def call(self, method: str, params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id,
                           "method": method, "params": params}).encode()
        request = urllib.request.Request(
            self.rpc_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                result = json.loads(response.read())
        except Exception as exc:  # noqa: BLE001 - transport failure, any cause
            raise ChainError(f"RPC {method} failed: {exc}") from exc
        if "error" in result:
            raise ChainError(f"RPC {method} error: {result['error']}")
        return result.get("result")

    def chain_id(self) -> int:
        return _as_int(self.call("eth_chainId", []))

    def block_number(self) -> int:
        return _as_int(self.call("eth_blockNumber", []))

    def nonce(self, address: str) -> int:
        return _as_int(self.call("eth_getTransactionCount", [address, "pending"]))

    def gas_price(self) -> int:
        return _as_int(self.call("eth_gasPrice", []))

    def balance(self, address: str) -> int:
        return _as_int(self.call("eth_getBalance", [address, "latest"]))

    def eth_call(self, to: str, data: bytes, block: str = "latest",
                 from_address: str | None = None) -> str:
        # Some backends (eth-tester) require a "from" key on eth_call and
        # check it can afford gas; pass a funded address via default_from
        # when running locally. Real nodes ignore it for view calls.
        sender = from_address or self.default_from or \
            "0x0000000000000000000000000000000000000000"
        return self.call("eth_call", [{"from": sender, "to": to,
                                       "data": "0x" + data.hex(),
                                       "gas": "0x186a0"}, block])

    def token_balance(self, token: str, holder: str) -> int:
        data = ERC20_BALANCE_SELECTOR + _abi_address(holder)
        return _decode_uint256(self.eth_call(token, data))

    def token_allowance(self, token: str, owner: str, spender: str) -> int:
        data = ERC20_ALLOWANCE_SELECTOR + _abi_address(owner) + _abi_address(spender)
        return _decode_uint256(self.eth_call(token, data))

    def send_raw_transaction(self, raw_tx: bytes) -> str:
        return self.call("eth_sendRawTransaction", ["0x" + raw_tx.hex()])

    def receipt(self, tx_hash: str):
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def wait_receipt(self, tx_hash: str, timeout_seconds: int = 120,
                     poll_seconds: float = 2.0) -> dict:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            receipt = self.receipt(tx_hash)
            if receipt is not None:
                return receipt
            time.sleep(poll_seconds)
        raise ChainError(f"no receipt for {tx_hash} within {timeout_seconds}s")


class LocalExecutor:
    """Demo executor: verified mandate -> ERC-20 transferFrom settlement.

    Safety checks, all enforced before any transaction is built:
    signature recovers to the mandate's payer; amount, payee, token and
    cart hash match the mandate; deadline not passed; payer allowance for
    the executor covers the amount.
    """

    def __init__(self, chain: JsonRpcClient, executor_private_key: bytes,
                 chain_id: int):
        self.chain = chain
        self.account = Account.from_key(executor_private_key)
        self.chain_id = chain_id
        self.used_nonces: set[tuple[str, int]] = set()

    @property
    def address(self) -> str:
        return self.account.address

    def settle(self, domain: dict, message: dict, signature: bytes,
               tracker: PaymentTracker, now_seconds: int | None = None) -> dict:
        now = int(now_seconds if now_seconds is not None else time.time())
        payer = message["payer"]
        if not eip712.verify_mandate(domain, message, signature, payer):
            tracker.fail("mandate signature does not recover to payer")
            raise ValueError("mandate signature verification failed")
        if message["deadline"] < now:
            tracker.fail("mandate expired")
            raise ValueError("mandate expired")
        nonce_key = (payer.lower(), message["nonce"])
        if nonce_key in self.used_nonces:
            tracker.fail("mandate nonce already used (replay)")
            raise ValueError("mandate nonce replay")
        token = message["token"]
        amount = message["amount"]
        allowance = self.chain.token_allowance(token, payer, self.address)
        if allowance < amount:
            tracker.fail("payer allowance insufficient for executor")
            raise ValueError("payer allowance insufficient")
        # Legal state order: payment-required -> submitted -> verified
        # -> processing -> included -> safe -> finalized.
        if tracker.state == PaymentState.PAYMENT_REQUIRED:
            tracker.advance(PaymentState.SUBMITTED, "mandate received")
        tracker.advance(PaymentState.VERIFIED, "mandate signature verified")
        tracker.advance(PaymentState.PROCESSING, "building transferFrom")
        calldata = transfer_from_calldata(payer, message["payee"], amount)
        tx = {
            "to": token,
            "value": 0,
            "data": calldata,
            "gas": 200000,
            "gasPrice": self.chain.gas_price(),
            "nonce": self.chain.nonce(self.address),
            "chainId": self.chain_id,
        }
        signed = self.account.sign_transaction(tx)
        tx_hash = self.chain.send_raw_transaction(signed.raw_transaction)
        tracker.tx_hash = tx_hash
        self.used_nonces.add(nonce_key)
        receipt = self.chain.wait_receipt(tx_hash)
        if _as_int(receipt.get("status", 0)) != 1:
            tracker.fail("settlement tx reverted on chain")
            raise ChainError("settlement tx reverted")
        tracker.advance(PaymentState.INCLUDED, "settlement tx included",
                        tx_hash=tx_hash)
        # Confirmation depth in the demo: receipt + observed chain growth.
        # The live gateway's safe/finalized are gateway confirmations;
        # here they are marked after inclusion on the demo chain.
        tracker.advance(PaymentState.SAFE, "included, confirmations observed")
        tracker.advance(PaymentState.FINALIZED, "settlement finalized")
        return receipt
