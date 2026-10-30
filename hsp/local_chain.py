"""Local EVM JSON-RPC bridge — demos and tests ONLY, never a chain claim.

Spins up an eth-tester chain behind a plain HTTP JSON-RPC endpoint so
the exact :class:`hsp.executor.JsonRpcClient` code path used for HSK
testnet can be exercised locally. The chain ID reported here (eth-tester
default 131277322940537) is a LOCAL chain id: any demo output built on
it must say "local EVM demo", never "HSK testnet".
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def start_local_rpc(host: str = "127.0.0.1", port: int = 0):
    """Start a local JSON-RPC server.

    Returns ``(server, rpc_url, w3)`` where ``w3`` is the web3.py handle
    for funding accounts and deploying contracts on the same chain.
    """
    from eth_tester import EthereumTester
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider

    w3 = Web3(EthereumTesterProvider(EthereumTester()))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                request = json.loads(raw)
            except ValueError:
                body = json.dumps({"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700,
                                             "message": "parse error"}}).encode()
                self._send(body)
                return
            try:
                params = request.get("params", [])
                # eth-tester's python API wants eth_call gas as an int,
                # while real JSON-RPC uses a hex quantity: normalize here
                # so the client can always send the standard hex form.
                if (request.get("method") == "eth_call" and params
                        and isinstance(params[0], dict)
                        and isinstance(params[0].get("gas"), str)):
                    params = [dict(params[0],
                                   gas=int(params[0]["gas"], 16))] + list(params[1:])
                response = w3.provider.make_request(
                    request.get("method"), params)
                response = dict(response)
                response.setdefault("jsonrpc", "2.0")
                response.setdefault("id", request.get("id"))
                # Web3.to_json handles AttributeDict/HexBytes values that
                # plain json.dumps cannot serialize (e.g. receipts).
                body = w3.to_json(response).encode()
            except Exception as exc:  # noqa: BLE001 - return a JSON-RPC error
                body = json.dumps({
                    "jsonrpc": "2.0", "id": request.get("id"),
                    "error": {"code": -32603, "message": str(exc)}}).encode()
            self._send(body)

        def _send(self, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://{host}:{server.server_address[1]}", w3


def compile_mock_token(solc_version: str = "0.8.20"):
    """Compile contracts/MockToken.sol with solcx; return (abi, bytecode)."""
    import solcx
    from pathlib import Path

    if solc_version not in solcx.get_installed_solc_versions():
        solcx.install_solc(solc_version)
    source = (Path(__file__).resolve().parents[1] / "contracts"
              / "MockToken.sol").read_text()
    compiled = solcx.compile_source(
        source, output_values=["abi", "bin"], solc_version=solc_version)
    contract = compiled["<stdin>:MockToken"]
    return contract["abi"], contract["bin"]
