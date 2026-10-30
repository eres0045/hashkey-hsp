"""HSK TESTNET demo — run from a network that can reach testnet.hsk.xyz.

IMPORTANT: from this project's VM, POSTs to https://testnet.hsk.xyz are
denied by the egress sentinel policy ("network access denied for this
task"), so this script CANNOT complete there. It is complete and ready
to run from any unblocked network (e.g. Ronit's own machine, or the
parent agent if its network scope allows HSK RPC):

  1. python3 scripts/make_test_wallets.py   # prints 3 test addresses
  2. Fund the payer address with tHSK (gas) at the faucet
     (https://faucet.hsk.xyz -> https://faucet.hashkeychain.net/)
     and with testnet USDC (transfer from a funded holder, or the
     faucet if it dispenses it).
  3. python3 scripts/testnet_demo.py

The script then runs the SAME agent flow as the local demo, against HSK
testnet (chain ID 133, testnet USDC 0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6),
and prints a JSON summary with the settlement tx hash. Verify that hash
with a direct RPC eth_getTransactionReceipt call — do not trust an
explorer page fetch for verification.

Settlement here uses the LocalExecutor (transferFrom after mandate
verification). The live gateway's EIP-3009/Permit2 broadcast replaces
it the day onboarding issues app_key/app_secret; until then the gateway
step is honestly labelled as pending, never claimed.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_account import Account

from hsp.agents import PaymentAgent, PaymentConditions, ReceivingAgent
from hsp.executor import JsonRpcClient, LocalExecutor, _abi_address, _abi_uint
from hsp.jwt_es256k import verify_jwt
from hsp.state_machine import PaymentTracker
from hsp.standin import StandinGateway
from eth_utils import keccak

RPC_URL = "https://testnet.hsk.xyz"
CHAIN_ID = 133
TESTNET_USDC = "0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6"
FAUCET = "https://faucet.hsk.xyz"
APPROVE_SELECTOR = keccak(b"approve(address,uint256)")[:4]
WALLETS_FILE = Path(__file__).resolve().parents[1] / "hidden_files" / "testnet-wallets.json"


def fail(message: str, extra: dict | None = None) -> "SystemExit":
    print(json.dumps({"ok": False, "error": message, **(extra or {})}, indent=2))
    raise SystemExit(2)


def main() -> dict:
    if not WALLETS_FILE.exists():
        fail("testnet wallets not generated yet",
             {"next_step": "run: python3 scripts/make_test_wallets.py"})
    wallets = json.loads(WALLETS_FILE.read_text())
    merchant_key = bytes.fromhex(wallets["merchant"]["private_key"])
    payer_key = bytes.fromhex(wallets["payer"]["private_key"])
    executor_key = bytes.fromhex(wallets["executor"]["private_key"])
    merchant = Account.from_key(merchant_key)
    payer_account = Account.from_key(payer_key)
    executor_account = Account.from_key(executor_key)

    chain = JsonRpcClient(RPC_URL, timeout=60)
    try:
        actual_chain = chain.chain_id()
    except Exception as exc:  # noqa: BLE001 - RPC unreachable from this network
        fail("HSK testnet RPC unreachable from this network",
             {"rpc_url": RPC_URL, "detail": str(exc),
              "note": "From the project VM this is the sentinel-policy POST "
                      "denial; run this script from an unblocked network."})
    if actual_chain != CHAIN_ID:
        fail("unexpected chain id", {"expected": CHAIN_ID, "got": actual_chain})

    gas_balance = chain.balance(payer_account.address)
    if gas_balance == 0:
        fail("payer has no tHSK for gas",
             {"payer": payer_account.address, "faucet": FAUCET})
    usdc_balance = chain.token_balance(TESTNET_USDC, payer_account.address)
    if usdc_balance < 1_000_000:
        fail("payer has less than 1.00 testnet USDC",
             {"payer": payer_account.address, "usdc_balance": usdc_balance})

    conditions = PaymentConditions(
        service_name="API credits", pay_to=merchant.address, coin="USDC",
        token_address=TESTNET_USDC, network="hsk-testnet",
        chain_id=CHAIN_ID, total_value="1.00", token_decimals=6)
    amount = conditions.amount_smallest_unit()

    receiving = ReceivingAgent("FORTEC", merchant.address, merchant_key)
    contents, cart_hash, jwt = receiving.build_cart(conditions, "cart-hsk-1",
                                                    "pay-hsk-1")
    verify_jwt(jwt, expected_address=merchant.address)

    executor = LocalExecutor(chain, executor_key, CHAIN_ID)
    gateway = StandinGateway(executor=executor)
    order = gateway.create_order(contents, jwt)

    payer = PaymentAgent(payer_key)
    approve_data = APPROVE_SELECTOR + _abi_address(executor_account.address) + _abi_uint(amount)
    approve_tx = {
        "to": TESTNET_USDC, "value": 0, "data": approve_data, "gas": 100000,
        "gasPrice": chain.gas_price(), "nonce": chain.nonce(payer.address),
        "chainId": CHAIN_ID,
    }
    signed = payer.account.sign_transaction(approve_tx)
    approve_hash = chain.send_raw_transaction(signed.raw_transaction)
    chain.wait_receipt(approve_hash)

    payee_before = chain.token_balance(TESTNET_USDC, merchant.address)
    domain, message = payer.build_mandate(conditions, cart_hash, nonce=1,
                                          deadline=int(time.time()) + 3600)
    signature = payer.sign_mandate(domain, message)
    assert payer.verify_mandate(domain, message, signature)
    result = gateway.pay_mandate(domain, message, signature, order["flow_id"])
    flow = gateway.get_flow(order["flow_id"])
    payee_after = chain.token_balance(TESTNET_USDC, merchant.address)
    receipt = chain.receipt(result["tx_hash"])

    summary = {
        "ok": True,
        "chain": "HSK TESTNET",
        "chain_id": CHAIN_ID,
        "rpc_url": RPC_URL,
        "token_address": TESTNET_USDC,
        "merchant_address": merchant.address,
        "payer_address": payer.address,
        "executor_address": executor_account.address,
        "cart_hash": cart_hash,
        "order_id": order["order_id"],
        "flow_id": order["flow_id"],
        "gateway": "standin (NOT live HSP gateway) — live gateway pending onboarding",
        "final_state": flow["state"],
        "state_history": [h["state"] for h in flow["history"]],
        "settlement_tx_hash": result["tx_hash"],
        "settlement_receipt_status": receipt.get("status") if receipt else None,
        "amount_smallest_unit": amount,
        "payee_balance_before": payee_before,
        "payee_balance_after": payee_after,
    }
    print(json.dumps(summary, indent=2, default=str))
    return summary


if __name__ == "__main__":
    main()
