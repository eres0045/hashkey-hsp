"""End-to-end tests on a LOCAL eth-tester chain (not HSK testnet).

Covers the happy path (via scripts/local_demo.py) plus the executor's
rejection paths: tampered mandate, expired mandate, and nonce replay.
All chain values here are local-chain values.
"""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from eth_account import Account
from eth_utils import keccak

from hsp.agents import PaymentAgent, PaymentConditions
from hsp.executor import JsonRpcClient, LocalExecutor
from hsp.local_chain import compile_mock_token, start_local_rpc
from hsp.state_machine import PaymentState, PaymentTracker
from local_demo import APPROVE_SELECTOR, run_demo
from hsp.executor import _abi_address, _abi_uint


class TestLocalDemo(unittest.TestCase):
    def test_full_demo_finalizes_with_exact_balances(self):
        summary = run_demo()
        self.assertEqual(summary["final_state"], "finalized")
        self.assertEqual(summary["state_history"], [
            "payment-required", "submitted", "verified", "processing",
            "included", "safe", "finalized"])
        self.assertEqual(summary["settlement_receipt_status"], 1)
        self.assertEqual(summary["payee_balance_after"]
                         - summary["payee_balance_before"],
                         summary["amount_smallest_unit"])
        self.assertEqual(summary["webhook_events"],
                         ["included", "safe", "finalized"])
        self.assertEqual(summary["webhook_rejected"], 0)
        self.assertEqual(summary["chain"], "LOCAL EVM DEMO ONLY (not HSK testnet)")


class TestExecutorRejections(unittest.TestCase):
    def setUp(self):
        self.server, self.rpc_url, self.w3 = start_local_rpc()
        self.chain_id = self.w3.eth.chain_id
        deployer = self.w3.eth.accounts[0]
        abi, bytecode = compile_mock_token()
        contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = contract.constructor().transact({"from": deployer})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        self.token = receipt.contractAddress
        self.payer_key = bytes.fromhex("d4" * 32)
        self.executor_key = bytes.fromhex("e5" * 32)
        self.payer = Account.from_key(self.payer_key)
        self.executor_account = Account.from_key(self.executor_key)
        for address in (self.payer.address, self.executor_account.address):
            self.w3.eth.send_transaction(
                {"from": deployer, "to": address, "value": 10 ** 18})
        token = self.w3.eth.contract(address=self.token, abi=abi)
        token.functions.mint(self.payer.address, 1_000_000_000).transact(
            {"from": deployer})
        self.chain = JsonRpcClient(self.rpc_url, default_from=deployer)
        self.executor = LocalExecutor(self.chain, self.executor_key,
                                      self.chain_id)
        self.agent = PaymentAgent(self.payer_key)
        self.conditions = PaymentConditions(
            service_name="API credits", pay_to=self.w3.eth.accounts[1],
            coin="mUSDC", token_address=self.token, network="local-evm-demo",
            chain_id=self.chain_id, total_value="10.00", token_decimals=6)
        self.amount = self.conditions.amount_smallest_unit()
        # Payer approves the executor for exactly the mandate amount.
        data = APPROVE_SELECTOR + _abi_address(self.executor.address) + _abi_uint(self.amount)
        tx = {"to": self.token, "value": 0, "data": data, "gas": 100000,
              "gasPrice": self.chain.gas_price(),
              "nonce": self.chain.nonce(self.payer.address),
              "chainId": self.chain_id}
        signed = self.agent.account.sign_transaction(tx)
        raw_hash = self.chain.send_raw_transaction(signed.raw_transaction)
        self.chain.wait_receipt(raw_hash)

    def tearDown(self):
        self.server.shutdown()

    def _mandate(self, nonce=1, deadline=None, amount_override=None):
        domain, message = self.agent.build_mandate(
            self.conditions, "ab" * 32, nonce=nonce,
            deadline=deadline or int(time.time()) + 3600)
        if amount_override is not None:
            message = dict(message, amount=amount_override)
        return domain, message, self.agent.sign_mandate(domain, message)

    def test_tampered_amount_rejected_and_tracked_failed(self):
        domain, message, signature = self._mandate()
        tampered = dict(message, amount=message["amount"] + 1)
        tracker = PaymentTracker("flow-tamper")
        with self.assertRaises(ValueError):
            self.executor.settle(domain, tampered, signature, tracker)
        self.assertEqual(tracker.state, PaymentState.FAILED)

    def test_expired_mandate_rejected(self):
        domain, message, signature = self._mandate(
            deadline=int(time.time()) - 10)
        tracker = PaymentTracker("flow-expired")
        with self.assertRaises(ValueError):
            self.executor.settle(domain, message, signature, tracker)
        self.assertEqual(tracker.state, PaymentState.FAILED)

    def test_nonce_replay_rejected(self):
        domain, message, signature = self._mandate(nonce=9)
        tracker1 = PaymentTracker("flow-first")
        self.executor.settle(domain, message, signature, tracker1)
        self.assertEqual(tracker1.state, PaymentState.FINALIZED)
        tracker2 = PaymentTracker("flow-replay")
        with self.assertRaises(ValueError):
            self.executor.settle(domain, message, signature, tracker2)
        self.assertEqual(tracker2.state, PaymentState.FAILED)


if __name__ == "__main__":
    unittest.main()
