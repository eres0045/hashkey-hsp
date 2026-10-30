"""ES256K JSON Web Tokens (secp256k1 ECDSA, as used for HSP merchant_authorization).

A JWT here is ``base64url(header).base64url(claims).base64url(r || s)`` with
header ``{"alg": "ES256K", "typ": "JWT"}``. The signature is ECDSA over the
SHA-256 digest of the ASCII signing input, with the 32-byte ``r`` and ``s``
concatenated (no recovery id in the token itself, per JWS).

This is deliberately NOT an Ethereum ``personal_sign`` signature: there is
no ``\\x19Ethereum Signed Message`` prefix. ``eth_keys`` is used directly
for raw secp256k1 signing/recovery.

Verification recovers the signer address by trying both recovery ids
(27/28), since the JWS form carries no ``v``.
"""

import base64
import hashlib
import json
import time
import uuid

from eth_keys import keys


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_jwt(private_key_bytes: bytes, claims: dict) -> str:
    """Sign *claims* with the secp256k1 private key; return the JWT string."""
    header = {"alg": "ES256K", "typ": "JWT"}
    signing_input = (
        b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    ).encode("ascii")
    digest = hashlib.sha256(signing_input).digest()
    signature = keys.PrivateKey(private_key_bytes).sign_msg_hash(digest)
    raw = signature.r.to_bytes(32, "big") + signature.s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + b64url_encode(raw)


def _recover_addresses(digest: bytes, r: int, s: int) -> list[str]:
    """All addresses recoverable from (r, s) across recovery ids.

    ECDSA recovery with a wrong ``v`` still yields *some* key, so a single
    recovery is meaningless on its own: the caller must match against the
    expected signer. eth_keys uses v in {0, 1}; some producers use {27, 28}.
    """
    addresses = []
    for v in (0, 1, 27, 28):
        try:
            sig = keys.Signature(vrs=(v, r, s))
            addresses.append(sig.recover_public_key_from_msg_hash(digest).to_address())
        except Exception:
            continue
    return addresses


def verify_jwt(token: str, expected_address: str | None = None):
    """Verify an ES256K JWT.

    Returns ``(claims, recovered_address)``. Raises ValueError on malformed
    tokens, bad signatures, or an address mismatch when *expected_address*
    is given. Expiry is checked against the current time when ``exp`` is
    present.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three parts")
    header_b64, claims_b64, sig_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(claims_b64))
        raw = b64url_decode(sig_b64)
    except Exception as exc:  # noqa: BLE001 - malformed token, any cause
        raise ValueError(f"malformed JWT: {exc}") from exc
    if header.get("alg") != "ES256K":
        raise ValueError(f"unexpected alg: {header.get('alg')!r}")
    if len(raw) != 64:
        raise ValueError("ES256K signature must be 64 bytes (r || s)")
    digest = hashlib.sha256(f"{header_b64}.{claims_b64}".encode("ascii")).digest()
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    candidates = _recover_addresses(digest, r, s)
    if not candidates:
        raise ValueError("signature recovery failed")
    if expected_address is not None:
        matches = [a for a in candidates
                   if a.lower() == expected_address.lower()]
        if not matches:
            raise ValueError(
                f"signer mismatch: recovered {candidates}, "
                f"expected {expected_address}")
        address = matches[0]
    else:
        # Ambiguous without an expected signer (any v recovers some key);
        # callers that need certainty must pass expected_address.
        address = candidates[0]
    exp = claims.get("exp")
    if exp is not None and time.time() > exp:
        raise ValueError("JWT expired")
    return claims, address


def build_merchant_authorization(
    private_key_bytes: bytes,
    merchant_name: str,
    cart_hash: str,
    ttl_seconds: int = 7200,
    now: int | None = None,
    jti: str | None = None,
) -> str:
    """Build the HSP ``merchant_authorization`` JWT for a Cart Mandate.

    Claims per the researched HSP flow: ``iss``, ``sub`` (merchant name),
    ``aud`` ("HashkeyMerchant"), ``iat``, ``exp``, ``jti``, ``cart_hash``.
    """
    issued = int(now if now is not None else time.time())
    claims = {
        "iss": merchant_name,
        "sub": merchant_name,
        "aud": "HashkeyMerchant",
        "iat": issued,
        "exp": issued + ttl_seconds,
        "jti": jti or uuid.uuid4().hex,
        "cart_hash": cart_hash,
    }
    return sign_jwt(private_key_bytes, claims)
