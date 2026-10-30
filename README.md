# FORTEC — Agent Payments & A2A Settlement (HSP)

HashKey Chain Horizon hackathon entry, team **FORTEC** (Ronit Shrimankar).
Track: **Agent Payments & A2A Settlement (HSP)** — the HashKey Merchant
gateway (HSP) flow where a receiving agent sets payment conditions, a
payment agent builds and signs a Payment Mandate, and the payment settles
on chain with full state-machine tracking.

**Submission deadline: Nov 1, 2026, 21:30 IST.** This repo is the build +
demo + verified report. Nothing here has been submitted to DoraHacks;
submission awaits Ronit's pre-submit checkpoint.

## What it is

Two agents, one settlement:

1. **Receiving agent** (`hsp/agents.py:ReceivingAgent`) — publishes
   payment conditions for a service (amount, coin, recipient, expiry)
   and turns them into a **Cart Mandate**: contents → Canonical JSON
   (RFC 8785) → SHA-256 → `cart_hash` → ES256K JWT
   `merchant_authorization` (claims `iss`, `sub` = merchant name,
   `aud` = `"HashkeyMerchant"`, `iat`, `exp`, `jti`, `cart_hash`).
2. **Payment agent** (`hsp/agents.py:PaymentAgent`) — builds the
   **Payment Mandate** from those conditions and signs it with the payer
   wallet (EIP-712), verifies its own signature, and hands it to an
   executor. The executor re-verifies before moving any funds and
   rejects expired mandates, wrong payers, wrong amounts and replayed
   nonces.
3. **Gateway client** (`hsp/gateway_client.py`) — HSP merchant API with
   HMAC-SHA256 headers (`X-App-Key` / `X-Signature` / `X-Timestamp` /
   `X-Nonce`, message
   `"{METHOD}\n{PATH}\n{QUERY}\n{bodyHash}\n{timestamp}\n{nonce}"`) and
   endpoints `POST /api/v1/merchant/orders`,
   `POST /merchant/orders/reusable`, `GET /merchant/payments`,
   `GET /merchant/payments/reusable`, `POST /api/v1/payment/pay-mandate`,
   `GET /api/v1/payment/flow/:id`.
4. **State machine** (`hsp/state_machine.py`) —
   `payment-required → submitted → verified → processing → included →
   safe → finalized` (`failed` terminal). Webhooks at
   included/safe/finalized/failed carry signed headers
   (`X-Signature: t=...,v1=...`, 2xx within 10s); polling
   `GET /merchant/payments` is the fallback.

## Proven so far (verified, not claimed)

- **22/22 tests green**: 18 unit tests (canonical JSON, ES256K JWT,
  HMAC headers, Cart Mandate hashing, state-machine legality, EIP-712
  sign/verify/tamper, webhook signature verification, gateway client
  request shape) + 4 local-chain end-to-end tests.
- **Local-chain demo** (`scripts/local_demo.py`): full flow on a local
  eth-tester EVM through the real HTTP JSON-RPC client path — Cart
  Mandate → stand-in order → EIP-712 mandate → payer approval →
  verified settlement → `finalized`, with exact balance deltas
  (payee +25,500,000, payer −25,500,000 smallest units for a 25.50
  payment) and verified webhook events
  (`included`, `safe`, `finalized`, 0 rejected). Settlement receipt
  status `1`, read back via RPC.
- **Executor rejections proven**: tampered amount → `failed`, expired
  mandate → `failed`, nonce replay → `failed`.

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
./run_tests.sh                        # 22 tests
python3 scripts/local_demo.py         # local-chain end-to-end demo
```

## Testnet demo (ready, not yet runnable from this VM)

```bash
python3 scripts/make_test_wallets.py  # testnet-only wallets, 0600, gitignored
# fund the printed payer address with tHSK (faucet) + testnet USDC
python3 scripts/testnet_demo.py       # HSK testnet, chain ID 133
```

Testnet wallets already generated (addresses only; keys live in
`hidden_files/testnet-wallets.json`, never committed):

- merchant: `0x924F42582C3c3e0336e755d3698C39B556D52464`
- payer: `0x70FB799cCB91ECc37Cc29824B54FF560a3fBFD60`
- executor: `0x6728594Fd54418409Df85Bd824420eE75615a8bC`

Faucet: https://faucet.hsk.xyz (redirects to
https://faucet.hashkeychain.net/). Testnet USDC:
`0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6`. Testnet USDT:
`0x372325443233fEbaC1F6998aC750276468c83CC6`. Mainnet is never touched.

## Judge runbook

1. `./run_tests.sh` — everything green, no network needed.
2. `python3 scripts/local_demo.py` — watch the state history run to
   `finalized` and the balances move by exactly the mandate amount.
3. When onboarding completes: put the issued `app_key`/`app_secret`
   into `GatewayClient(HOSTS["qa"], ...)` (never into git), re-confirm
   the flagged schema details below against the live gateway, then run
   `scripts/testnet_demo.py` from an unblocked network.
4. Verify any testnet tx hash with a direct RPC
   `eth_getTransactionReceipt` call — never via an explorer page fetch.

## Honest limits — read before judging

1. **No live HSK testnet transaction has been sent yet.** From this
   VM, every POST to `https://testnet.hsk.xyz` is denied by the egress
   sentinel policy (`network access denied for this task`, HTTP 403;
   GET works, WebSocket is also 403), and alternative public RPC hosts
   (dRPC, Ankr, thirdweb, the testnet explorer host) are unreachable
   (connection failures). The testnet demo script is complete and
   ready, but it needs an unblocked network to run. All chain values
   reported so far are LOCAL-chain values, labelled as such everywhere.
2. **No live HSP gateway payment has happened.** Merchant onboarding
   (QA console) is Cloudflare-blocked from this VM and is Ronit's
   own-browser task (reminder Oct 31 ~09:44 IST); no
   `app_key`/`app_secret` exists yet. The demo settles through a
   clearly-labelled local stand-in (`hsp/standin.py`) + `LocalExecutor`
   (`transferFrom` after mandate verification). The live gateway's
   EIP-3009 `transferWithAuthorization` / Permit2 broadcast is the
   step that replaces it — it is pending, not claimed.
3. **Mainnet deployment is blocked and not attempted.** Ronit holds no
   crypto and has no card, so mainnet HSK is unobtainable; no
   purchase/swap route is proposed. Note the rule consequence: the
   hackathon's demo selection requires mainnet deployment, so a
   testnet-only submission carries a real disqualification risk for
   that stage. Testnet submission by Nov 1 is the agreed plan.
4. **Three schema details must be re-confirmed at onboarding** (the
   live merchant docs are JS-rendered and could not be re-read from
   this VM, so the implementation follows the flow researched
   2026-10-29): the exact nesting of `payment_request`/`details`
   inside Cart Mandate `contents`; whether `bodyHash` is hex (as
   implemented) or base64; and the exact webhook signed-payload
   construction (`t.payload`, as implemented) plus the live gateway's
   EIP-712 domain/types (the demo uses its own documented domain
   `FORTEC HSP Payment Mandate` v1). Each is flagged in code where it
   is assumed.
5. **Confirmation depth is simplified in the demo.** The local
   executor marks `safe`/`finalized` after inclusion on the demo
   chain; the live gateway's safe/finalized are gateway confirmations
   with their own depth rules.
6. **Funding is never relayed** (same discipline as the SafePay
   relayer): the executor only moves the payer's own pre-approved
   tokens, never holds custody.

## Chain facts

- HSK testnet: RPC `https://testnet.hsk.xyz`, chain ID 133, faucet
  `https://faucet.hsk.xyz`, explorer `https://testnet-explorer.hsk.xyz`.
- HSK mainnet: RPC `https://mainnet.hsk.xyz`, chain ID 177, explorer
  `https://hashkey.blockscout.com`. No mainnet faucet. **Not used.**
- Gateway hosts: QA `https://merchant-qa.hashkeymerchant.com`,
  staging `https://merchant-stg.hashkeymerchant.com`, production
  `https://hsp.hashkey.com`. Docs: `hashkey-merchant.github.io/en`,
  `docs.hskchain.net`.

## Layout

```
hsp/            agents, mandate, canonical JSON, ES256K JWT, HMAC,
                gateway client, state machine, webhook, EIP-712,
                executor + JSON-RPC client, stand-in, local chain bridge
tests/          unit tests + local-chain end-to-end tests
scripts/        local_demo.py, testnet_demo.py, make_test_wallets.py
contracts/      MockToken.sol (local demo ERC-20 only, never public)
hidden_files/   testnet-wallets.json (0600, gitignored — keys, never commit)
```

## Security

Test wallets only. No key material is committed: `hidden_files/` is
gitignored, wallet files are mode 0600, and no secret appears in code,
tests, or this README.
