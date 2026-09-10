#!/usr/bin/env python3
"""EUWallet protocol test receiver. Never emits governed identity admission evidence.
The deliberately public EUWallet fixture signing key authorizes TEST credentials only.
"""
import argparse
import base64
import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

BASE = "https://kanalen.actum.network/identity-test"
RESPONSE = BASE + "/response"
EPOCH = 1790000000  # EUWallet's existing test clock, never a production freshness assertion.
VCT = "urn:eudi:pid:1"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64")
    result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(result) != value:
        raise ValueError("noncanonical base64")
    return result


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def unpack(raw):
    return json.loads(raw, object_pairs_hook=unique)


def signed(payload, key, cert):
    header = {"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [base64.b64encode(cert).decode()]}
    data = ".".join(b64(json.dumps(x, separators=(",", ":")).encode()) for x in (header, payload))
    r, s = decode_dss_signature(key.sign(data.encode(), ec.ECDSA(hashes.SHA256())))
    return data + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_jwt(compact, key, typ):
    h, p, s = compact.split(".")
    header = unpack(unb64(h))
    if header.get("alg") != "ES256" or header.get("typ") != typ or "crit" in header:
        raise ValueError("unsupported JWT")
    signature = unb64(s)
    if len(signature) != 64:
        raise ValueError("invalid signature")
    key.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
               (h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))
    return unpack(unb64(p))


def verify_presentation(compact, nonce, issuer_key):
    if len(compact) > 65536:
        raise ValueError("oversize presentation")
    parts = compact.split("~")
    if not 3 <= len(parts) <= 66:
        raise ValueError("invalid disclosure envelope")
    issuer = verify_jwt(parts[0], issuer_key, "dc+sd-jwt")
    if issuer.get("iss") != "https://issuer.example" or issuer.get("vct") != VCT or issuer.get("_sd_alg") != "sha-256":
        raise ValueError("not a supported test credential")
    if not isinstance(issuer.get("exp"), int) or issuer["exp"] <= EPOCH or issuer.get("iat", EPOCH + 1) > EPOCH:
        raise ValueError("test credential outside validity")
    jwk = issuer["cnf"]["jwk"]
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("unsupported holder key")
    x, y = unb64(jwk["x"]), unb64(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("invalid holder key")
    holder = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    kb = verify_jwt(parts[-1], holder, "kb+jwt")
    if kb.get("aud") != "rp.example" or kb.get("nonce") != nonce or kb.get("iat") != EPOCH:
        raise ValueError("holder request mismatch")
    if kb.get("sd_hash") != b64(hashlib.sha256(("~".join(parts[:-1]) + "~").encode()).digest()):
        raise ValueError("disclosure binding mismatch")
    seen = set()
    for disclosure in parts[1:-1]:
        value = unpack(unb64(disclosure))
        if not isinstance(value, list) or len(value) != 3 or value[1] != "age_over_18" or value[2] is not True or value[1] in seen:
            raise ValueError("unexpected test disclosure")
        if b64(hashlib.sha256(disclosure.encode()).digest()) not in issuer.get("_sd", []):
            raise ValueError("invalid disclosure digest")
        seen.add(value[1])
    if seen != {"age_over_18"}:
        raise ValueError("missing test claim")
    return hashlib.sha256(compact.encode()).hexdigest()


class Receiver:
    def __init__(self, database, fixtures):
        self.key = serialization.load_der_private_key((fixtures / "rp.pkcs8.der").read_bytes(), None)
        self.cert = (fixtures / "rp.der").read_bytes()
        self.lock = threading.Lock()
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, token TEXT, owner TEXT, chain TEXT, nonce TEXT, expires INTEGER, status TEXT, proof TEXT)")
        self.db.commit()

    def create(self, body):
        if set(body) != {"owner", "chain"} or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{96}", v) or v == "0" * 96 for v in body.values()):
            raise ValueError("invalid wallet binding")
        with self.lock:
            now = int(time.time())
            self.db.execute("DELETE FROM sessions WHERE expires < ?", (now - 86400,))
            if self.db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 512:
                raise ValueError("receiver capacity reached")
            sid, token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            nonce = b64(hashlib.sha384(json.dumps([sid, body["owner"], body["chain"], "identity-test"]).encode()).digest())
            expires = now + 300
            self.db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, 'pending', '')", (sid, hashlib.sha256(token.encode()).hexdigest(), body["owner"], body["chain"], nonce, expires))
            self.db.commit()
        return {"id": sid, "token": token, "expires": expires, "invocation": "eudi-openid4vp://?" + urlencode({"client_id": "rp.example", "request_uri": BASE + "/request/" + sid})}

    def request(self, sid):
        with self.lock:
            row = self.db.execute("SELECT nonce, expires, status FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row or row[1] <= time.time() or row[2] != "pending":
            raise ValueError("session unavailable")
        return signed({"client_id": "rp.example", "iss": "rp.example", "aud": "wallet.example", "response_type": "vp_token", "response_mode": "direct_post", "response_uri": RESPONSE, "nonce": row[0], "state": sid, "iat": EPOCH, "exp": EPOCH + 300, "purpose": "ActiveChain TEST credential attachment. No government verification or chain identity registration.", "dcql_query": {"credentials": [{"id": "identity", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}, "claims": [{"path": ["age_over_18"]}]}]}}, self.key, self.cert)

    def respond(self, raw):
        if re.search(rb"%(?![0-9a-fA-F]{2})", raw):
            raise ValueError("bad form encoding")
        fields = unique(parse_qsl(raw.decode("ascii"), keep_blank_values=True, strict_parsing=True))
        if not set(fields) <= {"state", "vp_token", "error", "error_description"}:
            raise ValueError("unknown response field")
        sid = fields.get("state", "")
        with self.lock:
            row = self.db.execute("SELECT nonce, expires, status FROM sessions WHERE id=?", (sid,)).fetchone()
            if not row or row[1] <= time.time() or row[2] != "pending":
                raise ValueError("session expired or consumed")
            status, proof = "rejected", ""
            try:
                if fields.get("error") == "access_denied" and "vp_token" not in fields:
                    status = "declined"
                else:
                    if "error" in fields or "error_description" in fields:
                        raise ValueError("invalid response")
                    token = unpack(fields["vp_token"])
                    if set(token) != {"identity"} or not isinstance(token["identity"], list) or len(token["identity"]) != 1:
                        raise ValueError("unexpected credentials")
                    proof = verify_presentation(token["identity"][0], row[0], self.key.public_key())
                    status = "test_verified"
            except Exception:
                pass  # No raw credential, personal claims or cryptographic errors are logged.
            self.db.execute("UPDATE sessions SET status=?, proof=? WHERE id=?", (status, proof, sid))
            self.db.commit()
        return {"redirect_uri": "activechain-wallet://identity-return?session=" + sid}

    def status(self, sid, token):
        with self.lock:
            row = self.db.execute("SELECT token, owner, chain, expires, status, proof FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row or not secrets.compare_digest(row[0], hashlib.sha256(token.encode()).hexdigest()):
            raise ValueError("unknown session")
        return {"id": sid, "owner": row[1], "chain": row[2], "status": "expired" if row[4] == "pending" and row[3] <= time.time() else row[4], "proof": row[5], "assurance": "test_only"}


def serve(receiver, port):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(10)
            super().setup()

        def log_message(self, *_):
            pass

        def dispatch(self):
            try:
                path = urlsplit(self.path).path
                if self.command == "GET" and path == "/identity-test/health":
                    result = {"status": "running", "assurance": "test_only"}
                elif self.command == "GET" and path.startswith("/identity-test/request/"):
                    result = receiver.request(path.rsplit("/", 1)[1])
                elif self.command == "GET" and path.startswith("/identity-test/status/"):
                    auth = self.headers.get("Authorization", "")
                    if not auth.startswith("Bearer "):
                        raise ValueError("unauthorized")
                    result = receiver.status(path.rsplit("/", 1)[1], auth[7:])
                elif self.command == "POST":
                    if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                        raise ValueError("invalid length")
                    length = int(self.headers["Content-Length"])
                    if not 0 < length <= 200000:
                        raise ValueError("oversize request")
                    self.connection.settimeout(10)
                    body = self.rfile.read(length)
                    content_type = self.headers.get("Content-Type", "").split(";")[0]
                    if path == "/identity-test/sessions" and content_type == "application/json" and length <= 1024:
                        result = receiver.create(unpack(body))
                    elif path == "/identity-test/response" and content_type == "application/x-www-form-urlencoded":
                        result = receiver.respond(body)
                    else:
                        raise ValueError("unknown route")
                else:
                    raise ValueError("unknown route")
                payload = result.encode() if isinstance(result, str) else json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/oauth-authz-req+jwt" if isinstance(result, str) else "application/json")
            except Exception:
                payload = b'{"error":"request_rejected"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        do_GET = dispatch
        do_POST = dispatch
    class Server(ThreadingHTTPServer):
        slots = threading.BoundedSemaphore(16)

        def process_request(self, request, address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.slots.release()

    Server(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    import os
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--port", type=int, default=49159)
    args = parser.parse_args()
    serve(Receiver(args.database, Path(__file__).parent / "fixtures"), args.port)
