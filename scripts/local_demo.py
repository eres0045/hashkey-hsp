"""Local-chain end-to-end demo (NOT HSK testnet — see README honest limits).

Runs the full agent flow on a local eth-tester chain through the real
JsonRpcClient HTTP path used for testnet:

  receiving agent builds Cart Mandate -> ES256K merchant_authorization
  -> stand-in gateway order -> payment agent EIP-712 mandate
  -> payer pre-approves executor -> executor verifies + settles
  -> state machine runs to finalized, webhooks delivered + verified

Prints a JSON summary. Every chain value in it is a LOCAL chain value.
"""

import json
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eth_account import Account
from eth_utils import keccak

from hsp.agents import PaymentAgent, PaymentConditions, ReceivingAgent
from hsp.executor import JsonRpcClient, LocalExecutor, _abi_address, _abi_uint
from hsp.jwt_es256k import verify_jwt
from hsp.local_chain import compile_mock_token, start_local_rpc
from hsp.standin import StandinGateway
from hsp.webhook import WebhookReceiver, make_webhook_handler

APPROVE_SELECTOR = keccak(b"approve(address,uint256)")[:4]
WEBHOOK_SECRET = "local-demo-webhook-secret"


def run_demo() -> dict:
    server, rpc_url, w3 = start_local_rpc()
    chain_id = w3.eth.chain_id
    deployer = w3.eth.accounts[0]

    abi, bytecode = compile_mock_token()
    token_contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = token_contract.constructor().transact({"from": deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    token_address = receipt.contractAddress

    merchant_key = bytes.fromhex("a1" * 32)
    payer_key = bytes.fromhex("b2" * 32)
    executor_key = bytes.fromhex("c3" * 32)
    merchant = Account.from_key(merchant_key)
    payer_account = Account.from_key(payer_key)

    for address in (merchant.address, payer_account.address,
                    Account.from_key(executor_key).address):
        w3.eth.send_transaction(
            {"from": deployer, "to": address, "value": 10 ** 18})

    token = w3.eth.contract(address=token_address, abi=abi)
    token.functions.mint(payer_account.address, 1_000_000_000).transact(
        {"from": deployer})

    chain = JsonRpcClient(rpc_url, default_from=deployer)
    assert chain.chain_id() == chain_id

    conditions = PaymentConditions(
        service_name="API credits", pay_to=merchant.address, coin="mUSDC",
        token_address=token_address, network="local-evm-demo",
        chain_id=chain_id, total_value="25.50", token_decimals=6)
    amount = conditions.amount_smallest_unit()

    receiving = ReceivingAgent("FORTEC", merchant.address, merchant_key)
    contents, cart_hash, jwt = receiving.build_cart(conditions, "cart-demo-1",
                                                    "pay-demo-1")
    _, jwt_signer = verify_jwt(jwt, expected_address=merchant.address)

    receiver = WebhookReceiver(WEBHOOK_SECRET)
    webhook_server = ThreadingHTTPServer(
        ("127.0.0.1", 0), make_webhook_handler(receiver))
    threading.Thread(target=webhook_server.serve_forever, daemon=True).start()
    webhook_url = f"http://127.0.0.1:{webhook_server.server_address[1]}/webhook"

    executor = LocalExecutor(chain, executor_key, chain_id)
    gateway = StandinGateway(executor=executor, webhook_url=webhook_url,
                             webhook_secret=WEBHOOK_SECRET)
    order = gateway.create_order(contents, jwt)

    # Payer pre-approves the executor (raw tx through the JsonRpcClient).
    payer = PaymentAgent(payer_key)
    approve_data = APPROVE_SELECTOR + _abi_address(executor.address) + _abi_uint(amount)
    approve_tx = {
        "to": token_address, "value": 0, "data": approve_data, "gas": 100000,
        "gasPrice": chain.gas_price(), "nonce": chain.nonce(payer.address),
        "chainId": chain_id,
    }
    signed = payer.account.sign_transaction(approve_tx)
    approve_hash = chain.send_raw_transaction(signed.raw_transaction)
    approve_receipt = chain.wait_receipt(approve_hash)
    assert approve_receipt is not None

    payee_before = chain.token_balance(token_address, merchant.address)
    payer_before = chain.token_balance(token_address, payer.address)

    domain, message = payer.build_mandate(conditions, cart_hash, nonce=1,
                                          deadline=int(time.time()) + 3600)
    signature = payer.sign_mandate(domain, message)
    assert payer.verify_mandate(domain, message, signature)
    result = gateway.pay_mandate(domain, message, signature, order["flow_id"])
    flow = gateway.get_flow(order["flow_id"])

    payee_after = chain.token_balance(token_address, merchant.address)
    payer_after = chain.token_balance(token_address, payer.address)
    settlement_receipt = chain.receipt(result["tx_hash"])

    webhook_server.shutdown()
    server.shutdown()

    summary = {
        "chain": "LOCAL EVM DEMO ONLY (not HSK testnet)",
        "chain_id": chain_id,
        "rpc_url": rpc_url,
        "token_address": token_address,
        "merchant_address": merchant.address,
        "payer_address": payer.address,
        "executor_address": executor.address,
        "cart_hash": cart_hash,
        "jwt_signer": jwt_signer,
        "order_id": order["order_id"],
        "flow_id": order["flow_id"],
        "gateway": "standin (NOT live HSP gateway)",
        "final_state": flow["state"],
        "state_history": [h["state"] for h in flow["history"]],
        "settlement_tx_hash": result["tx_hash"],
        "settlement_receipt_status": settlement_receipt.get("status"),
        "settlement_block": settlement_receipt.get(
            "blockNumber", settlement_receipt.get("block_number")),
        "amount_smallest_unit": amount,
        "payee_balance_before": payee_before,
        "payee_balance_after": payee_after,
        "payer_balance_before": payer_before,
        "payer_balance_after": payer_after,
        "webhook_events": [e["state"] for e in receiver.events],
        "webhook_rejected": receiver.rejected,
    }
    assert flow["state"] == "finalized", flow
    assert payee_after - payee_before == amount
    assert payer_before - payer_after == amount
    assert "finalized" in summary["webhook_events"]
    return summary


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, default=str))
