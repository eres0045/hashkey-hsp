"""Generate TESTNET-ONLY wallets for the HSK testnet demo.

Writes hidden_files/testnet-wallets.json (mode 0600, gitignored) and
prints ONLY the addresses. Private keys never leave that file: never
paste them in chat, never commit them, never reuse them on mainnet.
Refuses to overwrite an existing file unless --force is passed.
"""

import json
import os
import sys
from pathlib import Path

from eth_account import Account

OUT = Path(__file__).resolve().parents[1] / "hidden_files" / "testnet-wallets.json"


def main():
    if OUT.exists() and "--force" not in sys.argv:
        print(f"{OUT} already exists; refusing to overwrite "
              "(pass --force to regenerate).")
        wallets = json.loads(OUT.read_text())
        for role, wallet in wallets.items():
            print(f"{role}: {wallet['address']}")
        return
    wallets = {}
    for role in ("merchant", "payer", "executor"):
        account = Account.create()
        wallets[role] = {
            "address": account.address,
            "private_key": account.key.hex(),
        }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(wallets, indent=2))
    os.chmod(OUT, 0o600)
    print("TESTNET-ONLY wallets written to hidden_files/testnet-wallets.json (0600).")
    print("Fund the payer address with tHSK + testnet USDC before running")
    print("scripts/testnet_demo.py. Addresses:")
    for role, wallet in wallets.items():
        print(f"  {role}: {wallet['address']}")


if __name__ == "__main__":
    main()
