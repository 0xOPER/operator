#!/usr/bin/env python3
"""verify-rekor.py -- offline ECDSA-P256 + RFC 6962 Merkle verifier for Rekor.

Verifies a Sigstore Rekor v1 log entry JSON (raw API map, `rekor-cli get --format json`,
or Sigstore bundle `tlogEntries[0]`) against a local artifact (e.g. CLAIMS.md) and a
trusted ECDSA-P256 SPKI public key (defaulting to repo `claims.pub`) with zero network
calls and zero third-party dependencies:
  1. Decodes canonicalized `body` and verifies `hashedrekord`/`rekord` SHA-256 == sha256(artifact).
  2. Verifies `spec.signature.publicKey` matches the trusted `--pubkey` PEM and verifies
     the ASN.1 DER ECDSA-P256-SHA256 `spec.signature.content` over the raw artifact bytes.
  3. Computes RFC 6962 leaf hash `SHA256(0x00 || raw_body)`, walks `inclusionProof.hashes`
     against `(logIndex, treeSize)` to recompute `rootHash`, and cross-checks `checkpoint`
     (plus optional `--root-hash`).

usage:
  verify-rekor.py --artifact <file> --entry <rekor-entry.json> [--pubkey <pem>] [--root-hash <hex>] [--json]
  verify-rekor.py --selftest
exit: 0 verified, 1 verification failed, 2 usage or unreadable input
"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# NIST P-256 (secp256r1) domain parameters
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


# Sigstore Public Good Rekor transparency log SPKI public key
# (LogID = sha256(SPKI_DER) = c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d)
REKOR_PUBLIC_GOOD_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
    "kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n"
    "-----END PUBLIC KEY-----\n"
)


class VerifyError(Exception):
    pass


def _p256_on_curve(pt):
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        return False
    return (y * y - (pow(x, 3, _P256_P) + _P256_A * x + _P256_B)) % _P256_P == 0


def _p256_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _p256_mul(k, pt):
    res = None
    addend = pt
    while k > 0:
        if k & 1:
            res = _p256_add(res, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    return res


def parse_p256_spki_pem(pem_bytes):
    text = pem_bytes.decode("ascii", errors="strict") if isinstance(pem_bytes, bytes) else str(pem_bytes)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("-----")]
    if not lines:
        raise VerifyError("empty PEM public key")
    try:
        der = base64.b64decode("".join(lines), validate=True)
    except Exception as e:
        raise VerifyError(f"invalid PEM base64 in public key: {e}") from e
    if len(der) != 91 or not der.startswith(_P256_SPKI_PREFIX):
        raise VerifyError("public key must be a 91-byte NIST P-256 SPKI key")
    qx = int.from_bytes(der[27:59], "big")
    qy = int.from_bytes(der[59:91], "big")
    if not _p256_on_curve((qx, qy)):
        raise VerifyError("public key point is not on NIST P-256")
    return (qx, qy)


def _encode_p256_spki_pem(pt):
    qx, qy = pt
    der = _P256_SPKI_PREFIX + qx.to_bytes(32, "big") + qy.to_bytes(32, "big")
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n".encode("ascii")


def _parse_ecdsa_der_sig(sig_bytes):
    if len(sig_bytes) < 8 or sig_bytes[0] != 0x30:
        raise VerifyError("ECDSA signature is not an ASN.1 SEQUENCE")
    seq_len = sig_bytes[1]
    idx = 2
    if seq_len & 0x80:
        nlen = seq_len & 0x7F
        if nlen == 0 or nlen > 2 or idx + nlen > len(sig_bytes):
            raise VerifyError("invalid ASN.1 length in ECDSA signature")
        seq_len = int.from_bytes(sig_bytes[idx:idx + nlen], "big")
        idx += nlen
    if idx + seq_len != len(sig_bytes):
        raise VerifyError("trailing or truncated bytes in ECDSA signature")
    vals = []
    for _ in range(2):
        if idx + 2 > len(sig_bytes) or sig_bytes[idx] != 0x02:
            raise VerifyError("expected ASN.1 INTEGER in ECDSA signature")
        ilen = sig_bytes[idx + 1]
        idx += 2
        if ilen <= 0 or idx + ilen > len(sig_bytes) or (sig_bytes[idx] & 0x80):
            raise VerifyError("invalid INTEGER encoding in ECDSA signature")
        vals.append(int.from_bytes(sig_bytes[idx:idx + ilen], "big"))
        idx += ilen
    if idx != len(sig_bytes):
        raise VerifyError("extra fields in ECDSA signature SEQUENCE")
    r, s = vals
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        raise VerifyError("ECDSA (r, s) out of P-256 scalar range")
    return r, s


def verify_p256_ecdsa_sha256(pub_pt, message_bytes, sig_der):
    r, s = _parse_ecdsa_der_sig(sig_der)
    z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")
    w = pow(s, -1, _P256_N)
    u1 = (z * w) % _P256_N
    u2 = (r * w) % _P256_N
    pt = _p256_add(_p256_mul(u1, (_P256_GX, _P256_GY)), _p256_mul(u2, pub_pt))
    if pt is None or (pt[0] % _P256_N) != r:
        raise VerifyError("ECDSA-P256 signature verification failed")
    return True


def _normalize_ip(ip):
    if not isinstance(ip, dict) or not ip:
        raise VerifyError("missing verification.inclusionProof in Rekor entry")
    raw_idx = ip.get("logIndex") if "logIndex" in ip else ip.get("LogIndex")
    raw_sz = ip.get("treeSize") if "treeSize" in ip else ip.get("TreeSize")
    raw_root = ip.get("rootHash") if "rootHash" in ip else ip.get("RootHash")
    raw_hashes = ip.get("hashes") if "hashes" in ip else ip.get("Hashes")
    raw_ckpt = ip.get("checkpoint") if "checkpoint" in ip else ip.get("Checkpoint")
    try:
        log_idx = int(raw_idx) if not isinstance(raw_idx, bool) else -1
        tree_sz = int(raw_sz) if not isinstance(raw_sz, bool) else -1
        if isinstance(raw_root, str) and not HEX64_RE.fullmatch(raw_root):
            raw_root = base64.b64decode(raw_root, validate=True).hex()
        hashes = []
        if not isinstance(raw_hashes, list):
            raise VerifyError("hashes must be a list")
        for h in raw_hashes:
            if not isinstance(h, str):
                raise VerifyError("audit hash must be a string")
            hashes.append(h if HEX64_RE.fullmatch(h) else base64.b64decode(h, validate=True).hex())
    except VerifyError:
        raise
    except Exception as e:
        raise VerifyError(f"malformed inclusionProof fields: {e}") from e
    return {
        "logIndex": log_idx,
        "treeSize": tree_sz,
        "rootHash": raw_root,
        "hashes": hashes,
        "checkpoint": raw_ckpt,
    }


def _rekor_log_id_hex(rekor_pem):
    text = rekor_pem.decode("ascii", errors="strict") if isinstance(rekor_pem, bytes) else str(rekor_pem)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("-----")]
    der = base64.b64decode("".join(lines), validate=True)
    return hashlib.sha256(der).hexdigest()


def _extract_entry(doc):
    if not isinstance(doc, dict) or not doc:
        raise VerifyError("entry JSON must be a non-empty object")
    try:
        target = doc
        if len(doc) == 1 and "body" not in doc and "CanonicalizedBody" not in doc and "verificationMaterial" not in doc:
            only = next(iter(doc.values()))
            if isinstance(only, dict):
                target = only
        if "body" in target and "verification" in target and isinstance(target.get("body"), str):
            ver = target.get("verification") or {}
            ip = _normalize_ip(ver.get("inclusionProof"))
            g_idx = target.get("logIndex")
            g_idx = int(g_idx) if isinstance(g_idx, int) and not isinstance(g_idx, bool) else ip["logIndex"]
            it = target.get("integratedTime")
            it = int(it) if isinstance(it, int) and not isinstance(it, bool) else None
            lid = str(target.get("logID") or "").lower() or None
            set_b64 = ver.get("signedEntryTimestamp")
            return {
                "body": target["body"],
                "integratedTime": it,
                "logID": lid,
                "logIndex": g_idx,
                "signedEntryTimestamp": set_b64 if isinstance(set_b64, str) else None,
                "inclusionProof": ip,
            }
        if "CanonicalizedBody" in target or "Body" in target:
            body_s = target.get("CanonicalizedBody") if isinstance(target.get("CanonicalizedBody"), str) else target.get("Body")
            if not isinstance(body_s, str):
                raise VerifyError("rekor-cli JSON lacks string CanonicalizedBody")
            ver = target.get("Verification") or target.get("verification") or {}
            ip = _normalize_ip(ver.get("InclusionProof") or ver.get("inclusionProof") or target.get("inclusionProof"))
            raw_g = target.get("LogIndex") if "LogIndex" in target else target.get("logIndex")
            g_idx = int(raw_g) if isinstance(raw_g, int) and not isinstance(raw_g, bool) else ip["logIndex"]
            raw_it = target.get("IntegratedTime") if "IntegratedTime" in target else target.get("integratedTime")
            it = int(raw_it) if isinstance(raw_it, int) and not isinstance(raw_it, bool) else None
            lid = str(target.get("LogID") or target.get("logID") or "").lower() or None
            set_b64 = ver.get("SignedEntryTimestamp") or ver.get("signedEntryTimestamp")
            return {
                "body": body_s,
                "integratedTime": it,
                "logID": lid,
                "logIndex": g_idx,
                "signedEntryTimestamp": set_b64 if isinstance(set_b64, str) else None,
                "inclusionProof": ip,
            }
        vm = target.get("verificationMaterial")
        if isinstance(vm, dict) and isinstance(vm.get("tlogEntries"), list) and vm["tlogEntries"]:
            t0 = vm["tlogEntries"][0]
            if not isinstance(t0, dict) or not isinstance(t0.get("canonicalizedBody"), str):
                raise VerifyError("Sigstore bundle tlogEntries[0] lacks canonicalizedBody")
            ip_raw = dict(t0.get("inclusionProof") or {})
            if "logIndex" not in ip_raw and "logIndex" in t0:
                ip_raw["logIndex"] = t0["logIndex"]
            ip = _normalize_ip(ip_raw)
            raw_g = t0.get("logIndex")
            g_idx = int(raw_g) if isinstance(raw_g, (int, str)) and not isinstance(raw_g, bool) else ip["logIndex"]
            raw_it = t0.get("integratedTime")
            it = int(raw_it) if isinstance(raw_it, (int, str)) and not isinstance(raw_it, bool) else None
            lid_raw = (t0.get("logId") or {}).get("keyId")
            lid = base64.b64decode(lid_raw).hex() if isinstance(lid_raw, str) else None
            set_b64 = (t0.get("inclusionPromise") or {}).get("signedEntryTimestamp")
            return {
                "body": t0["canonicalizedBody"],
                "integratedTime": it,
                "logID": lid,
                "logIndex": g_idx,
                "signedEntryTimestamp": set_b64 if isinstance(set_b64, str) else None,
                "inclusionProof": ip,
            }
    except VerifyError:
        raise
    except Exception as e:
        raise VerifyError(f"malformed Rekor entry JSON: {e}") from e
    raise VerifyError("unrecognized Rekor entry JSON structure")


def rfc6962_leaf_hash(raw_leaf_bytes):
    return hashlib.sha256(b"\x00" + raw_leaf_bytes).digest()


def rfc6962_node_hash(left_bytes, right_bytes):
    return hashlib.sha256(b"\x01" + left_bytes + right_bytes).digest()


def verify_checkpoint_note(ckpt_text, tree_size, root_hash_hex, rekor_pt, expected_log_id_hex):
    text = str(ckpt_text or "")
    if "\n\n" not in text:
        raise VerifyError("Rekor checkpoint lacks signed C2SP note separator")
    note_body, sig_block = text.split("\n\n", 1)
    lines = note_body.splitlines()
    if len(lines) != 3 or not lines[0].strip():
        raise VerifyError("malformed Rekor checkpoint note body")
    try:
        ckpt_sz = int(lines[1].strip())
        ckpt_root = base64.b64decode(lines[2].strip(), validate=True).hex()
    except Exception as e:
        raise VerifyError(f"invalid checkpoint size/hash encoding: {e}") from e
    if ckpt_sz != tree_size or ckpt_root != root_hash_hex.lower():
        raise VerifyError("checkpoint note does not match inclusionProof (treeSize/rootHash)")
    key_hint = bytes.fromhex(expected_log_id_hex[:8])
    signed_payload = (note_body + "\n").encode("utf-8")
    verified_sig = False
    for sln in sig_block.splitlines():
        s = sln.strip()
        if not s:
            continue
        if s.startswith("\u2014 "):
            s = s[2:].strip()
        elif s.startswith("-- "):
            s = s[3:].strip()
        else:
            continue
        parts = s.rsplit(" ", 1)
        if len(parts) != 2:
            continue
        try:
            raw_sig = base64.b64decode(parts[1], validate=True)
        except Exception:
            continue
        if len(raw_sig) <= 4 or raw_sig[:4] != key_hint:
            continue
        verify_p256_ecdsa_sha256(rekor_pt, signed_payload, raw_sig[4:])
        verified_sig = True
        break
    if not verified_sig:
        raise VerifyError("checkpoint C2SP signature missing or failed Rekor key verification")
    return True


def verify_signed_entry_timestamp(ent, rekor_pt, expected_log_id_hex):
    set_b64 = ent.get("signedEntryTimestamp")
    if not set_b64:
        raise VerifyError("missing verification.signedEntryTimestamp in Rekor entry")
    int_time = ent.get("integratedTime")
    log_id = (ent.get("logID") or "").lower()
    log_idx = ent.get("logIndex")
    if int_time is None or not isinstance(log_idx, int) or not log_id:
        raise VerifyError("Rekor entry lacks integratedTime/logID/logIndex required for SET verification")
    if log_id != expected_log_id_hex.lower():
        raise VerifyError(f"Rekor entry logID {log_id[:16]}... != pinned Rekor logID {expected_log_id_hex[:16]}...")
    try:
        set_der = base64.b64decode(set_b64, validate=True)
    except Exception as e:
        raise VerifyError(f"invalid signedEntryTimestamp base64: {e}") from e
    jcs_payload = json.dumps({
        "body": ent["body"],
        "integratedTime": int_time,
        "logID": log_id,
        "logIndex": log_idx,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    verify_p256_ecdsa_sha256(rekor_pt, jcs_payload, set_der)
    return True


def verify_inclusion_proof(leaf_hash, log_index, tree_size, audit_hashes_hex, root_hash_hex):
    if not isinstance(log_index, int) or isinstance(log_index, bool) or log_index < 0:
        raise VerifyError(f"invalid logIndex {log_index!r}")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size <= log_index:
        raise VerifyError(f"invalid treeSize {tree_size!r} for logIndex {log_index!r}")
    if not isinstance(root_hash_hex, str) or not HEX64_RE.fullmatch(root_hash_hex):
        raise VerifyError("invalid rootHash hex")
    if not isinstance(audit_hashes_hex, list):
        raise VerifyError("hashes must be a list")
    fn = log_index
    sn = tree_size - 1
    cur = leaf_hash
    for h_hex in audit_hashes_hex:
        if not isinstance(h_hex, str) or not HEX64_RE.fullmatch(h_hex):
            raise VerifyError(f"invalid audit hash {h_hex!r}")
        if sn == 0:
            raise VerifyError("audit path too long for treeSize")
        sib = bytes.fromhex(h_hex)
        if (fn & 1) == 1 or fn == sn:
            cur = rfc6962_node_hash(sib, cur)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            cur = rfc6962_node_hash(cur, sib)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise VerifyError("audit path ended before reaching Merkle root")
    if cur.hex() != root_hash_hex.lower():
        raise VerifyError(f"Merkle root mismatch: computed {cur.hex()[:16]}... != {root_hash_hex[:16]}...")
    return True


def verify_artifact_entry(artifact_path, entry_doc, pubkey_path=None, expected_root_hex=None,
                          rekor_pubkey_pem=None):
    with open(artifact_path, "rb") as f:
        art_bytes = f.read()
    art_sha = hashlib.sha256(art_bytes).hexdigest()
    if pubkey_path is None:
        default_pub = os.path.join(ROOT, "claims.pub")
        if os.path.isfile(default_pub):
            pubkey_path = default_pub
    if not pubkey_path or not os.path.isfile(pubkey_path):
        raise VerifyError("trusted --pubkey PEM required to authenticate Rekor entry")
    with open(pubkey_path, "rb") as pf:
        trusted_pt = parse_p256_spki_pem(pf.read())

    rekor_pem = rekor_pubkey_pem if rekor_pubkey_pem is not None else REKOR_PUBLIC_GOOD_PEM
    rekor_pt = parse_p256_spki_pem(rekor_pem)
    rekor_log_id = _rekor_log_id_hex(rekor_pem)

    ent = _extract_entry(entry_doc)
    body_b64 = ent.get("body")
    try:
        raw_body = base64.b64decode(body_b64, validate=True)
        body_json = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        raise VerifyError(f"invalid Rekor body payload: {e}") from e
    kind = str(body_json.get("kind") or "").lower()
    if kind not in ("hashedrekord", "rekord"):
        raise VerifyError(f"unsupported Rekor entry kind {kind!r}")
    spec = body_json.get("spec") or {}
    hash_obj = ((spec.get("data") or {}).get("hash") or {})
    alg = str(hash_obj.get("algorithm") or "").lower()
    val = str(hash_obj.get("value") or "").lower()
    if alg != "sha256" or not HEX64_RE.fullmatch(val):
        raise VerifyError(f"entry spec.data.hash must be sha256 hex, got {alg}:{val[:16]}")
    if val != art_sha:
        raise VerifyError(f"artifact sha256 {art_sha[:16]}... != Rekor entry {val[:16]}...")

    sig_obj = spec.get("signature") or {}
    sig_b64 = sig_obj.get("content")
    pk_b64 = (sig_obj.get("publicKey") or {}).get("content")
    if not isinstance(sig_b64, str) or not sig_b64 or not isinstance(pk_b64, str) or not pk_b64:
        raise VerifyError("Rekor entry lacks spec.signature.content or publicKey.content")
    try:
        sig_der = base64.b64decode(sig_b64, validate=True)
        entry_pem = base64.b64decode(pk_b64, validate=True)
    except Exception as e:
        raise VerifyError(f"invalid signature/publicKey base64 in Rekor body: {e}") from e
    entry_pt = parse_p256_spki_pem(entry_pem)
    if entry_pt != trusted_pt:
        raise VerifyError("Rekor entry publicKey does not match trusted --pubkey")
    verify_p256_ecdsa_sha256(trusted_pt, art_bytes, sig_der)

    ip = ent["inclusionProof"]
    tree_log_idx = ip["logIndex"]
    global_log_idx = ent["logIndex"]
    tree_sz = ip["treeSize"]
    root_hex = ip["rootHash"]
    hashes = ip["hashes"]
    leaf = rfc6962_leaf_hash(raw_body)
    verify_inclusion_proof(leaf, tree_log_idx, tree_sz, hashes, root_hex)
    if not ip.get("checkpoint"):
        raise VerifyError("missing inclusionProof.checkpoint; Rekor STH signature is required")
    verify_checkpoint_note(ip["checkpoint"], tree_sz, root_hex, rekor_pt, rekor_log_id)
    verify_signed_entry_timestamp(ent, rekor_pt, rekor_log_id)
    if expected_root_hex is not None:
        if not HEX64_RE.fullmatch(expected_root_hex) or expected_root_hex.lower() != str(root_hex).lower():
            raise VerifyError("inclusionProof rootHash does not match pinned --root-hash")
    return {
        "ok": True,
        "artifact_sha256": art_sha,
        "kind": kind,
        "log_id": rekor_log_id,
        "log_index": global_log_idx,
        "tree_log_index": tree_log_idx,
        "tree_size": tree_sz,
        "root_hash": str(root_hex).lower(),
    }


def _sign_p256_der(priv_d, msg_bytes):
    z = int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big")
    while True:
        k = secrets.randbelow(_P256_N - 1) + 1
        pt = _p256_mul(k, (_P256_GX, _P256_GY))
        r = pt[0] % _P256_N
        if r == 0:
            continue
        s = (pow(k, -1, _P256_N) * (z + r * priv_d)) % _P256_N
        if s != 0:
            break

    def _der_int(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return bytes([0x02, len(b)]) + b

    rb, sb = _der_int(r), _der_int(s)
    return bytes([0x30, len(rb) + len(sb)]) + rb + sb


def _build_merkle_fixture(leaves_bytes, target_idx):
    """Build a genuine RFC 6962 5-leaf Merkle tree and inclusion proof for selftest."""
    lhashes = [rfc6962_leaf_hash(b) for b in leaves_bytes]

    def root_of(nodes):
        n = len(nodes)
        if n == 1:
            return nodes[0]
        k = 1
        while (k << 1) < n:
            k <<= 1
        return rfc6962_node_hash(root_of(nodes[:k]), root_of(nodes[k:]))

    def path_of(nodes, m):
        n = len(nodes)
        if n == 1:
            return []
        k = 1
        while (k << 1) < n:
            k <<= 1
        if m < k:
            return path_of(nodes[:k], m) + [root_of(nodes[k:]).hex()]
        return path_of(nodes[k:], m - k) + [root_of(nodes[:k]).hex()]

    return root_of(lhashes).hex(), path_of(lhashes, target_idx)


def selftest():
    ok = 0
    bad = 0

    def check(cond, label):
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"FAIL {label}", file=sys.stderr)

    # Verify repo claims.pub parses cleanly as NIST P-256 SPKI and pinned Rekor key matches Public Good LogID
    repo_pub = os.path.join(ROOT, "claims.pub")
    if os.path.isfile(repo_pub):
        check(_p256_on_curve(parse_p256_spki_pem(open(repo_pub, "rb").read())),
              "A0 repo claims.pub is a valid NIST P-256 SPKI key")
    check(_rekor_log_id_hex(REKOR_PUBLIC_GOOD_PEM) == "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
          "A0a pinned REKOR_PUBLIC_GOOD_PEM matches Public Good LogID")
    repo_claims = os.path.join(ROOT, "CLAIMS.md")
    repo_entry = os.path.join(ROOT, "claims-rekor.json")
    if os.path.isfile(repo_claims) and os.path.isfile(repo_entry) and os.path.isfile(repo_pub):
        real_doc = json.load(open(repo_entry, encoding="utf-8"))
        real_res = verify_artifact_entry(repo_claims, real_doc, pubkey_path=repo_pub)
        check(real_res["ok"] and real_res["log_index"] >= real_res["tree_log_index"],
              f"A0b real repo CLAIMS.md + claims-rekor.json authenticates STH & SET: {real_res}")

    with tempfile.TemporaryDirectory(prefix="rekor-st.") as td:
        art_bytes = b"# falsifiable claims fixture\n"
        art = os.path.join(td, "CLAIMS.md")
        with open(art, "wb") as f:
            f.write(art_bytes)
        priv_d = 0x1A2B3C4D5E6F77889900AABBCCDDEEFF112233445566778899AABBCCDDEEFF01 % (_P256_N - 1) + 1
        pub_pt = _p256_mul(priv_d, (_P256_GX, _P256_GY))
        pub_pem = _encode_p256_spki_pem(pub_pt)
        pub_path = os.path.join(td, "trusted.pub")
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        sig_der = _sign_p256_der(priv_d, art_bytes)

        # Synthetic test Rekor log keypair (separate from artifact signer!)
        rekor_d = 0x5566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344 % (_P256_N - 1) + 1
        rekor_pt_test = _p256_mul(rekor_d, (_P256_GX, _P256_GY))
        rekor_pem_test = _encode_p256_spki_pem(rekor_pt_test)
        rekor_lid_test = _rekor_log_id_hex(rekor_pem_test)

        art_sha = hashlib.sha256(art_bytes).hexdigest()
        target_body = json.dumps({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": art_sha}},
                "signature": {
                    "content": base64.b64encode(sig_der).decode("ascii"),
                    "publicKey": {"content": base64.b64encode(pub_pem).decode("ascii")},
                },
            },
        }, sort_keys=True).encode("utf-8")
        body_b64 = base64.b64encode(target_body).decode("ascii")
        leaves = [b"leaf0", b"leaf1", target_body, b"leaf3", b"leaf4"]
        root_hex, audit_hex = _build_merkle_fixture(leaves, 2)
        ckpt_b64 = base64.b64encode(bytes.fromhex(root_hex)).decode("ascii")
        note_body = f"rekor.sigstore.test - 1\n5\n{ckpt_b64}"
        ckpt_sig_der = _sign_p256_der(rekor_d, (note_body + "\n").encode("utf-8"))
        ckpt_sig_b64 = base64.b64encode(bytes.fromhex(rekor_lid_test[:8]) + ckpt_sig_der).decode("ascii")
        ckpt = f"{note_body}\n\n\u2014 rekor.sigstore.test {ckpt_sig_b64}\n"
        int_time = 1790000000
        global_idx = 102
        set_jcs = json.dumps({
            "body": body_b64,
            "integratedTime": int_time,
            "logID": rekor_lid_test,
            "logIndex": global_idx,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        set_sig_b64 = base64.b64encode(_sign_p256_der(rekor_d, set_jcs)).decode("ascii")
        entry = {
            "deadbeef": {
                "body": body_b64,
                "integratedTime": int_time,
                "logID": rekor_lid_test,
                "logIndex": global_idx,
                "verification": {
                    "inclusionProof": {
                        "logIndex": 2,
                        "treeSize": 5,
                        "rootHash": root_hex,
                        "hashes": audit_hex,
                        "checkpoint": ckpt,
                    },
                    "signedEntryTimestamp": set_sig_b64,
                },
            }
        }
        res = verify_artifact_entry(art, entry, pubkey_path=pub_path, expected_root_hex=root_hex,
                                    rekor_pubkey_pem=rekor_pem_test)
        check(res["ok"] and res["log_index"] == 102 and res["tree_log_index"] == 2 and res["tree_size"] == 5,
              "A valid ECDSA-P256 + 5-leaf RFC 6962 + authenticated STH & SET proof verifies")

        # Self-fabricated proof signed with wrong Rekor log key MUST fail against pinned REKOR_PUBLIC_GOOD_PEM
        try:
            verify_artifact_entry(art, entry, pubkey_path=pub_path)
            check(False, "A1b self-fabricated Rekor tree signed by attacker key must fail against Public Good key")
        except VerifyError as e:
            check("checkpoint" in str(e).lower() or "signature" in str(e).lower() or "logid" in str(e).lower(),
                  f"A1b attacker-signed Rekor STH rejected: {e}")

        # Tampered checkpoint signature must fail
        bad_ckpt_ent = json.loads(json.dumps(entry))
        bad_raw_sig = bytearray(bytes.fromhex(rekor_lid_test[:8]) + ckpt_sig_der)
        bad_raw_sig[-1] ^= 0x01
        bad_ckpt_b64 = base64.b64encode(bytes(bad_raw_sig)).decode("ascii")
        bad_ckpt_ent["deadbeef"]["verification"]["inclusionProof"]["checkpoint"] = (
            f"{note_body}\n\n\u2014 rekor.sigstore.test {bad_ckpt_b64}\n"
        )
        try:
            verify_artifact_entry(art, bad_ckpt_ent, pubkey_path=pub_path, rekor_pubkey_pem=rekor_pem_test)
            check(False, "A1c tampered checkpoint signature must fail")
        except VerifyError:
            check(True, "A1c tampered checkpoint signature rejected")

        # Tampered signedEntryTimestamp must fail
        bad_set_ent = json.loads(json.dumps(entry))
        bad_set_raw = bytearray(base64.b64decode(set_sig_b64))
        bad_set_raw[-1] ^= 0x01
        bad_set_ent["deadbeef"]["verification"]["signedEntryTimestamp"] = base64.b64encode(bytes(bad_set_raw)).decode("ascii")
        try:
            verify_artifact_entry(art, bad_set_ent, pubkey_path=pub_path, rekor_pubkey_pem=rekor_pem_test)
            check(False, "A1d tampered signedEntryTimestamp must fail")
        except VerifyError:
            check(True, "A1d tampered signedEntryTimestamp rejected")

        # rekor-cli get --format json PascalCase + dict Body shape verifies
        cli_entry = {
            "Body": {"HashedRekordObj": {}},
            "CanonicalizedBody": body_b64,
            "IntegratedTime": int_time,
            "LogID": rekor_lid_test,
            "LogIndex": global_idx,
            "Verification": {
                "InclusionProof": {
                    "LogIndex": 2,
                    "TreeSize": 5,
                    "RootHash": root_hex,
                    "Hashes": audit_hex,
                    "Checkpoint": ckpt,
                },
                "SignedEntryTimestamp": set_sig_b64,
            },
        }
        check(verify_artifact_entry(art, cli_entry, pubkey_path=pub_path, rekor_pubkey_pem=rekor_pem_test)["ok"],
              "A2 rekor-cli get --format json shape verifies")

        # Self-signed proof with untrusted key MUST fail against trusted.pub
        other_pt = _p256_mul(priv_d + 1, (_P256_GX, _P256_GY))
        other_pub = os.path.join(td, "other.pub")
        with open(other_pub, "wb") as f:
            f.write(_encode_p256_spki_pem(other_pt))
        try:
            verify_artifact_entry(art, entry, pubkey_path=other_pub, rekor_pubkey_pem=rekor_pem_test)
            check(False, "B untrusted signing key must fail")
        except VerifyError as e:
            check("does not match trusted" in str(e), f"B untrusted key message: {e}")

        # Forged ECDSA signature bytes with matching publicKey MUST fail
        forged_sig = bytearray(sig_der)
        forged_sig[-1] ^= 0x01
        forged_body = json.dumps({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": art_sha}},
                "signature": {
                    "content": base64.b64encode(bytes(forged_sig)).decode("ascii"),
                    "publicKey": {"content": base64.b64encode(pub_pem).decode("ascii")},
                },
            },
        }, sort_keys=True).encode("utf-8")
        f_root, f_audit = _build_merkle_fixture([forged_body], 0)
        forged_entry = {
            "x": {
                "body": base64.b64encode(forged_body).decode("ascii"),
                "verification": {
                    "inclusionProof": {"logIndex": 0, "treeSize": 1, "rootHash": f_root, "hashes": f_audit}
                },
            }
        }
        try:
            verify_artifact_entry(art, forged_entry, pubkey_path=pub_path, rekor_pubkey_pem=rekor_pem_test)
            check(False, "B2 forged ECDSA signature must fail")
        except VerifyError as e:
            check("signature" in str(e).lower() or "ecdsa" in str(e).lower() or "integer" in str(e).lower(),
                  f"B2 forged signature message: {e}")

        # Tampered Merkle sibling hash must fail
        bad_sib = json.loads(json.dumps(entry))
        h0 = bad_sib["deadbeef"]["verification"]["inclusionProof"]["hashes"][0]
        bad_sib["deadbeef"]["verification"]["inclusionProof"]["hashes"][0] = (
            ("0" if h0[0] != "0" else "1") + h0[1:]
        )
        try:
            verify_artifact_entry(art, bad_sib, pubkey_path=pub_path, rekor_pubkey_pem=rekor_pem_test)
            check(False, "C tampered audit path must fail")
        except VerifyError as e:
            check("Merkle root mismatch" in str(e), f"C root mismatch message: {e}")

        # Malformed bundle raises VerifyError (rc 1), never KeyError/VOID
        try:
            verify_artifact_entry(art, {"verificationMaterial": {"tlogEntries": [{}]}}, pubkey_path=pub_path,
                                  rekor_pubkey_pem=rekor_pem_test)
            check(False, "D malformed bundle must raise VerifyError")
        except VerifyError:
            check(True, "D malformed bundle raises VerifyError")

    if bad == 0:
        print(f"selftest: OK ({ok} checks: ECDSA-P256, RFC 6962 proof, checkpoint, tamper rejections)")
        return 0
    print("selftest: FAIL", file=sys.stderr)
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--artifact", default=None)
    ap.add_argument("--entry", default=None)
    ap.add_argument("--pubkey", default=None)
    ap.add_argument("--root-hash", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.artifact or not args.entry:
        print("usage: verify-rekor.py --artifact <file> --entry <rekor-entry.json> [--pubkey <pem>] [--root-hash <hex>] [--json] | --selftest",
              file=sys.stderr)
        return 2
    if not os.path.isfile(args.artifact) or not os.path.isfile(args.entry):
        print("verify-rekor: missing --artifact or --entry file", file=sys.stderr)
        return 2
    try:
        with open(args.entry, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print(f"verify-rekor: VOID -- {e}", file=sys.stderr)
        return 2
    try:
        res = verify_artifact_entry(args.artifact, doc, pubkey_path=args.pubkey,
                                    expected_root_hex=args.root_hash)
    except VerifyError as e:
        print(f"verify-rekor: FAIL -- {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"verify-rekor: VOID -- {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res, sort_keys=True))
    else:
        print(
            f"verify-rekor: OK sha256={res['artifact_sha256']} "
            f"logIndex={res['log_index']} tree_log_index={res['tree_log_index']} "
            f"treeSize={res['tree_size']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
