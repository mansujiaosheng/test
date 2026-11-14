#!/usr/bin/env python3
# -*- coding: ascii -*-
"""T-BOX 10.230.164.3:8443 client-cert acceptance matrix + TLS-trick matrix.

Read-only against the target (one TCP connection per case, no brute force).
Generates the client-cert shapes into 04_SOLVE/tbox-mtls/pki/, probes, and
writes JSON + TXT evidence into 03_EVIDENCE/tbox-mtls/.

Usage:
    python 04_SOLVE/tbox-mtls/make_matrix.py            # gen if missing, then probe
    python 04_SOLVE/tbox-mtls/make_matrix.py --regen    # force regenerate material
    python 04_SOLVE/tbox-mtls/make_matrix.py --probe-only
"""
import datetime as dt
import json
import os
import re
import socket
import ssl
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PKI = os.path.join(HERE, "pki")
EV = os.path.join(ROOT, "03_EVIDENCE", "tbox-mtls")
TARGET = (os.environ.get("TBOX_HOST", "10.225.139.3"), int(os.environ.get("TBOX_PORT", "8443")))

# Subject DER of the real CA, lifted verbatim from the server's CertificateRequest
# (03_EVIDENCE/tbox/0015_certreq_decoded.txt). Tag 0x13 = PrintableString.
REAL_ROOT_DN_DER = bytes.fromhex(
    "3025312330210603550403131a43563620466c65657420446961676e6f73746963"
    "7320526f6f74"
)
# AKI of the live server leaf == SHA-1(SPKI) of the real root (unknown to us).
REAL_AKI = bytes.fromhex("6591B3ED6CB02B421B6446F962EF85DECAD5120A")  # round-2 root

NOW = dt.datetime(2026, 11, 14, 1, 0, 0, tzinfo=dt.timezone.utc)
VALID_FROM = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
VALID_TO = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------- material ---
def save_key(name, key):
    path = os.path.join(PKI, name + ".key")
    with open(path, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return path


def save_cert(name, *certs):
    path = os.path.join(PKI, name + ".pem")
    with open(path, "wb") as fh:
        for c in certs:
            fh.write(c.public_bytes(serialization.Encoding.PEM))
    return path


def pprintstr(value):
    """Force PrintableString (matches the real root DN's ASN.1 type)."""
    return x509.NameAttribute(NameOID.COMMON_NAME, value,
                             _type=_ASN1_TYPE.PrintableString)


try:  # cryptography >= 42 exposes _ASN1Type from cryptography.x509.name
    from cryptography.x509.name import _ASN1Type as _ASN1_TYPE
except Exception:  # pragma: no cover
    _ASN1_TYPE = None


def cn_utf8(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def cn_printable(value):
    if _ASN1_TYPE is None:
        return cn_utf8(value)
    return x509.Name([pprintstr(value)])


def build(
    subject,
    key,
    *,
    issuer=None,
    issuer_key=None,
    ca=False,
    path_len=None,
    eku=("client",),
    san=None,
    sk=None,
    aki=None,
    ku=None,
    extra=(),
    nb=VALID_FROM,
    na=VALID_TO,
):
    if issuer is None:
        issuer = subject
    if issuer_key is None:
        issuer_key = key
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    if ku is not None:
        b = b.add_extension(x509.KeyUsage(**ku), critical=True)
    else:
        b = b.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if ca:
        b = b.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True
        )
    else:
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    if eku:
        oids = {
            "client": ExtendedKeyUsageOID.CLIENT_AUTH,
            "server": ExtendedKeyUsageOID.SERVER_AUTH,
            "code": ExtendedKeyUsageOID.CODE_SIGNING,
            "any": ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        }
        b = b.add_extension(
            x509.ExtendedKeyUsage([oids[e] for e in eku]), critical=False
        )
    if san is not None:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san]), critical=False
        )
    if sk is not None:
        b = b.add_extension(x509.SubjectKeyIdentifier(sk), critical=False)
    if aki is not None:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier(key_identifier=aki,
                                        authority_cert_issuer=None,
                                        authority_cert_serial_number=None),
            critical=False,
        )
    for ext, crit in extra:
        b = b.add_extension(ext, critical=crit)
    alg = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = b.sign(issuer_key, alg)
    return cert


def gen():
    os.makedirs(PKI, exist_ok=True)
    man = []

    def note(name, certs, keyname, label):
        man.append(
            {
                "name": name,
                "label": label,
                "files": [os.path.join(PKI, n + ".pem").replace(ROOT + os.sep, "") for n in certs],
                "key": (name + ".key") if keyname else None,
            }
        )

    p256 = lambda: ec.generate_private_key(ec.SECP256R1())
    p384 = lambda: ec.generate_private_key(ec.SECP384R1())
    rsa2048 = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # ---- A. self-signed client certs (no relation to the real root) --------
    k = p256(); c = build(cn_utf8("tbox"), k, eku=("client",), san=["tbox"],
                          sk=x509.SubjectKeyIdentifier.from_public_key(k.public_key()).digest)
    save_key("s01_cn_tbox", k); save_cert("s01_cn_tbox", c)
    note("s01_cn_tbox", ["s01_cn_tbox"], True,
         "self-signed EC P-256, CN=tbox, EKU=clientAuth, SAN=DNS:tbox")

    k = rsa2048(); c = build(cn_utf8("tbox"), k, eku=("client",), san=["tbox"])
    save_key("s02_rsa2048", k); save_cert("s02_rsa2048", c)
    note("s02_rsa2048", ["s02_rsa2048"], True, "self-signed RSA-2048, CN=tbox, EKU=clientAuth")

    k = p384(); c = build(cn_utf8("tbox"), k, eku=("client",), san=["tbox"])
    save_key("s03_p384", k); save_cert("s03_p384", c)
    note("s03_p384", ["s03_p384"], True, "self-signed EC P-384 (secp384r1), CN=tbox")

    k = p256(); c = build(cn_utf8("tbox"), k, eku=("client",), san=["tbox"],
                          nb=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
                          na=dt.datetime(2020, 12, 31, tzinfo=dt.timezone.utc))
    save_key("s04_expired", k); save_cert("s04_expired", c)
    note("s04_expired", ["s04_expired"], True, "self-signed, notAfter=2020-12-31 (expired)")

    k = p256(); c = build(cn_utf8("tbox"), k, eku=("client",), san=["tbox"],
                          nb=dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc),
                          na=dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc))
    save_key("s05_notyet", k); save_cert("s05_notyet", c)
    note("s05_notyet", ["s05_notyet"], True, "self-signed, notBefore=2027-06-01 (not yet valid)")

    k = p256(); c = build(cn_utf8("tbox"), k, eku=(), san=["tbox"])
    save_key("s06_no_eku", k); save_cert("s06_no_eku", c)
    note("s06_no_eku", ["s06_no_eku"], True, "self-signed, NO ExtendedKeyUsage extension")

    k = p256(); c = build(cn_utf8("tbox"), k, eku=("server",), san=["tbox"])
    save_key("s07_eku_server", k); save_cert("s07_eku_server", c)
    note("s07_eku_server", ["s07_eku_server"], True, "self-signed, EKU=serverAuth only")

    k = p256(); c = build(cn_utf8("tbox"), k, eku=("client",), san=None)
    save_key("s08_no_san", k); save_cert("s08_no_san", c)
    note("s08_no_san", ["s08_no_san"], True, "self-signed, no SubjectAlternativeName")

    k = p256(); c = build(x509.Name([]), k, eku=("client",), san=None)
    save_key("s09_empty_subject", k); save_cert("s09_empty_subject", c)
    note("s09_empty_subject", ["s09_empty_subject"], True, "self-signed, EMPTY subject DN")

    k = p256(); c = build(cn_utf8("tbox"), k, ca=True, eku=("client",), san=["tbox"])
    save_key("s10_ca_true", k); save_cert("s10_ca_true", c)
    note("s10_ca_true", ["s10_ca_true"], True, "self-signed with CA:TRUE + keyCertSign")

    k = p256(); c = build(cn_utf8("CV6 Fleet Diagnostics Root"), k, ca=False,
                          eku=("client",), san=["tbox"])
    save_key("s11_cn_root", k); save_cert("s11_cn_root", c)
    note("s11_cn_root", ["s11_cn_root"], True,
         "self-signed leaf named CN=CV6 Fleet Diagnostics Root (CA:FALSE)")

    k = p256(); c = build(cn_utf8("tbox"), k, eku=("client",), san=["tbox"],
                          aki=REAL_AKI)
    save_key("s12_aki_forged", k); save_cert("s12_aki_forged", c)
    note("s12_aki_forged", ["s12_aki_forged"], True,
         "self-signed leaf with AKI copied from the real root (47:6E:90:...)")

    k = ed25519.Ed25519PrivateKey.generate(); c = build(cn_utf8("tbox"), k,
                                                        eku=("client",), san=["tbox"])
    save_key("s13_ed25519", k); save_cert("s13_ed25519", c)
    note("s13_ed25519", ["s13_ed25519"], True, "self-signed Ed25519, CN=tbox")

    # ---- B. fake CA named/fingerprinted like the real root, + leaves -------
    def fake_ca(tag, label, keygen=p256, sk=None, extra=()):
        kk = keygen()
        cc = build(cn_printable("CV6 Fleet Diagnostics Root"), kk, ca=True,
                   eku=(), san=None,
                   sk=(sk if sk is not None else x509.SubjectKeyIdentifier.from_public_key(kk.public_key()).digest),
                   extra=extra)
        save_key("ca_" + tag, kk); save_cert("ca_" + tag, cc)
        note("ca_" + tag, ["ca_" + tag], True, label)
        return kk, cc

    def leaf(tag, ca_key, ca_cert, label):
        lk = p256()
        lc = build(cn_utf8("tbox"), lk, issuer=ca_cert.subject, issuer_key=ca_key,
                   eku=("client",), san=["tbox"],
                   aki=x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()).digest)
        save_key("leaf_" + tag, lk)
        save_cert("leaf_" + tag, lc)
        chain = save_cert("chain_" + tag + "_leaf_first", lc, ca_cert)
        save_cert("chain_" + tag + "_ca_first", ca_cert, lc)
        note("leaf_" + tag, ["leaf_" + tag, "chain_" + tag + "_leaf_first",
                             "chain_" + tag + "_ca_first"], True, label)
        return lc, chain

    ca1k, ca1c = fake_ca("samedn", "fake CA, CN=CV6 Fleet Diagnostics Root (PrintableString), own key")
    leaf("samedn", ca1k, ca1c, "leaf signed by fake same-DN CA")

    ca2k, ca2c = fake_ca("sameski", "fake CA, same DN + forged SKI == real root AKI",
                        sk=REAL_AKI)
    leaf("sameski", ca2k, ca2c, "leaf signed by fake same-DN/same-SKI CA")

    ca3k, ca3c = fake_ca(
        "namecon", "fake CA, same DN + nameConstraints permitted DNS:.tbox",
        extra=[(x509.NameConstraints(permitted_subtrees=[x509.DNSName(".tbox")],
                                     excluded_subtrees=None), True)],
    )
    leaf("namecon", ca3k, ca3c, "leaf signed by fake same-DN CA with nameConstraints")

    ca4k, ca4c = fake_ca(
        "policies", "fake CA, same DN + certificatePolicies + AIA-less",
        extra=[(x509.CertificatePolicies([x509.PolicyInformation(
            x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), None)]), False)],
    )
    leaf("policies", ca4k, ca4c, "leaf signed by fake same-DN CA with certificatePolicies")

    ca5k, ca5c = fake_ca("rsa", "fake CA, same DN, RSA-2048", keygen=rsa2048)
    leaf("rsa", ca5k, ca5c, "leaf signed by fake same-DN RSA CA")

    # ---- C. VPN material from the shipped .ovpn ---------------------------
    ovpn = os.path.join(ROOT, "cybercar-competition-ed3e7d452581978ccae13421-"
                              "usr_b2ad80d021e26b5fb4b02b8619302912.ovpn")
    if os.path.exists(ovpn):
        txt = open(ovpn, "r", encoding="utf-8", errors="replace").read()
        blocks = re.findall(r"<(\w[\w-]*)>\s*(-----BEGIN [^-]+-----.*?-----END [^-]+-----)\s*</\1>",
                            txt, re.S)
        for tag, pem in blocks:
            fn = os.path.join(PKI, "ovpn_" + tag.replace("-", "_") + ".pem")
            with open(fn, "w", encoding="ascii", newline="\n") as fh:
                fh.write(pem + "\n")
            man.append({"name": "ovpn_" + tag, "label": "extracted from .ovpn <%s>" % tag,
                        "files": [os.path.relpath(fn, ROOT).replace(os.sep, "/")],
                        "key": None})

    with open(os.path.join(EV, "0101_pki_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(man, fh, indent=1, ensure_ascii=False)

    # human readable manifest
    lines = ["# generated client-cert material (04_SOLVE/tbox-mtls/pki)", ""]
    for m in man:
        for f in m["files"]:
            p = os.path.join(ROOT, f.replace("/", os.sep))
            if not p.endswith(".pem") or not os.path.exists(p):
                continue
            try:
                cert = x509.load_pem_x509_certificate(open(p, "rb").read())
            except Exception:
                continue
            eku = []
            try:
                eku = [e._name for e in cert.extensions.get_extension_for_class(
                    x509.ExtendedKeyUsage).value]
            except Exception:
                eku = ["<none>"]
            san = "<none>"
            try:
                san = str(cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value)
            except Exception:
                pass
            ski = "<none>"
            try:
                ski = cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value.digest.hex(":").upper()
            except Exception:
                pass
            aki = "<none>"
            try:
                aki = cert.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier).value.key_identifier.hex(":").upper()
            except Exception:
                pass
            now = "<n/a>"
            try:
                from cryptography.hazmat.primitives.asymmetric import dsa  # noqa: F401
                now = "valid" if cert.not_valid_before_utc <= NOW <= cert.not_valid_after_utc \
                    else "OUT-OF-WINDOW"
            except Exception:
                pass
            lines.append(
                "%-46s subj=%s | iss=%s | key=%s | eku=%s | san=%s | %s..%s | %s | ski=%s | aki=%s"
                % (f,
                   cert.subject.rfc4514_string(),
                   cert.issuer.rfc4514_string(),
                   type(cert.public_key()).__name__,
                   ",".join(eku), san,
                   cert.not_valid_before_utc.strftime("%Y-%m-%d"),
                   cert.not_valid_after_utc.strftime("%Y-%m-%d"),
                   now, ski, aki)
            )
    # byte-level check: does any generated CA subject match the real CA DN DER?
    lines.append("")
    lines.append("real CA subject DER (from CertificateRequest): " + REAL_ROOT_DN_DER.hex().upper())
    for f in sorted(os.listdir(PKI)):
        if not f.endswith(".pem"):
            continue
        try:
            cert = x509.load_pem_x509_certificate(open(os.path.join(PKI, f), "rb").read())
        except Exception:
            continue
        if cert.subject.public_bytes() == REAL_ROOT_DN_DER:
            lines.append("BYTE-EQUAL subject DER to real CA: " + f)
    with open(os.path.join(EV, "0102_pki_cert_manifest.txt"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("[gen] %d material entries -> %s" % (len(man), PKI))


# ----------------------------------------------------------------- probes ---
ALERT_RE = re.compile(r"alert (?:number )?(\d+)|(TLSV1\d?_ALERT_[A-Z_]+|SSLV3_ALERT_[A-Z_]+)")


def classify(exc):
    s = str(exc)
    reason = getattr(exc, "reason", None)
    num = None
    m = re.search(r"alert number (\d+)", s)
    if m:
        num = int(m.group(1))
    else:
        m2 = re.search(r"\((\d+)\)", s)
        if m2 and "alert" in s.lower():
            num = int(m2.group(1))
    return {"exception": type(exc).__name__, "reason": reason, "alert_number": num,
            "message": s}


def probe(case):
    row = {"case": case["name"], "desc": case.get("desc", "")}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if case.get("tls12"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if case.get("ciphers"):
        ctx.set_ciphers(case["ciphers"])
    if case.get("alpn"):
        ctx.set_alpn_protocols(case["alpn"])
    if case.get("cert"):
        ctx.load_cert_chain(case["cert"], case["key"])
    sni = case.get("sni", "tbox")
    t0 = time.time()
    try:
        raw = socket.create_connection(TARGET, timeout=case.get("timeout", 10))
        ss = ctx.wrap_socket(raw, server_hostname=(None if sni == "" else sni))
        row["handshake"] = "OK"
        row["tls_version"] = ss.version()
        row["cipher"] = ss.cipher()
        row["alpn_negotiated"] = ss.selected_alpn_protocol()
        try:
            peer = ss.getpeercert(binary_form=True)
            pc = x509.load_der_x509_certificate(peer)
            row["peer_subject"] = pc.subject.rfc4514_string()
            row["peer_issuer"] = pc.issuer.rfc4514_string()
        except Exception:
            pass
        ss.sendall(b"GET / HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n")
        buf = b""
        while True:
            chunk = ss.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        row["http_head"] = buf[:400].decode("latin-1")
        ss.close()
    except Exception as exc:  # noqa: BLE001
        row["handshake"] = "FAIL"
        row.update(classify(exc))
        transient = ("10054" in str(exc) or "reset" in str(exc).lower()
                     or "timed out" in str(exc).lower())
        if transient:
            for attempt in range(2, 5):
                time.sleep(0.8)
                r2 = probe(case)
                r2["attempts"] = attempt
                if r2["handshake"] == "OK" or r2.get("alert_number"):
                    row = r2
                    break
                row = r2
    row["elapsed_s"] = round(time.time() - t0, 3)
    return row


def cases():
    P = lambda n: os.path.join(PKI, n + ".pem")
    K = lambda n: os.path.join(PKI, n + ".key")
    out = [
        dict(name="A00_no_cert", desc="no client certificate at all"),
        dict(name="A01_selfsigned_cn_tbox", cert=P("s01_cn_tbox"), key=K("s01_cn_tbox"),
             desc="self-signed P-256 CN=tbox EKU=clientAuth SAN=tbox"),
        dict(name="A02_rsa2048", cert=P("s02_rsa2048"), key=K("s02_rsa2048"),
             desc="self-signed RSA-2048 CN=tbox"),
        dict(name="A03_p384", cert=P("s03_p384"), key=K("s03_p384"),
             desc="self-signed secp384r1 CN=tbox"),
        dict(name="A04_expired", cert=P("s04_expired"), key=K("s04_expired"),
             desc="self-signed expired (2020)"),
        dict(name="A05_not_yet_valid", cert=P("s05_notyet"), key=K("s05_notyet"),
             desc="self-signed notBefore 2027-06"),
        dict(name="A06_no_eku", cert=P("s06_no_eku"), key=K("s06_no_eku"),
             desc="self-signed, no EKU extension"),
        dict(name="A07_eku_serverauth_only", cert=P("s07_eku_server"), key=K("s07_eku_server"),
             desc="self-signed, EKU=serverAuth only"),
        dict(name="A08_no_san", cert=P("s08_no_san"), key=K("s08_no_san"),
             desc="self-signed, no SAN"),
        dict(name="A09_empty_subject", cert=P("s09_empty_subject"), key=K("s09_empty_subject"),
             desc="self-signed, empty subject"),
        dict(name="A10_ca_true_selfsigned", cert=P("s10_ca_true"), key=K("s10_ca_true"),
             desc="self-signed CA:TRUE + keyCertSign + EKU clientAuth"),
        dict(name="A11_cn_is_cv6_root", cert=P("s11_cn_root"), key=K("s11_cn_root"),
             desc="self-signed leaf CN=CV6 Fleet Diagnostics Root"),
        dict(name="A12_aki_forged", cert=P("s12_aki_forged"), key=K("s12_aki_forged"),
             desc="self-signed leaf with AKI = real root SKI"),
        dict(name="A13_ed25519", cert=P("s13_ed25519"), key=K("s13_ed25519"),
             desc="self-signed Ed25519"),
        dict(name="B01_fakeca_samedn_leaf", cert=P("chain_samedn_leaf_first"), key=K("leaf_samedn"),
             desc="fake CA same DN (PrintableString) + leaf, leaf first"),
        # B02 (CA-first ordering) cannot go through python ssl: load_cert_chain
        # requires the key to match the FIRST cert. Covered by openssl s_client
        # in 04_SOLVE/tbox-mtls/tls_tricks.sh instead.
        dict(name="B03_fakeca_sameski_leaf", cert=P("chain_sameski_leaf_first"), key=K("leaf_sameski"),
             desc="fake CA same DN + forged SKI == real AKI"),
        dict(name="B04_fakeca_nameconstraints", cert=P("chain_namecon_leaf_first"), key=K("leaf_namecon"),
             desc="fake CA same DN + nameConstraints"),
        dict(name="B05_fakeca_policies", cert=P("chain_policies_leaf_first"), key=K("leaf_policies"),
             desc="fake CA same DN + certificatePolicies"),
        dict(name="B06_fakeca_rsa", cert=P("chain_rsa_leaf_first"), key=K("leaf_rsa"),
             desc="fake CA same DN, RSA-2048"),
        dict(name="B07_only_ca_no_leaf", cert=P("ca_sameski"), key=K("ca_sameski"),
             desc="present only the CA cert as the client cert (no leaf)"),
        dict(name="B08_leaf_only_no_ca", cert=P("leaf_samedn"), key=K("leaf_samedn"),
             desc="leaf signed by unshipped fake CA, no CA in chain"),
        dict(name="B09_vpn_client", cert=P("ovpn_cert"), key=P("ovpn_key"),
             desc="VPN client cert+key shipped in .ovpn (issuer VPN CA)"),
        dict(name="B10_vpn_chain", cert=P("ovpn_chain_vpn"), key=P("ovpn_key"),
             desc="VPN client cert + VPN CA chain"),
    ]
    # build VPN chain file for B10
    ch = os.path.join(PKI, "ovpn_chain_vpn.pem")
    try:
        parts = [open(os.path.join(PKI, "ovpn_cert.pem"), "rb").read(),
                 open(os.path.join(PKI, "ovpn_ca.pem"), "rb").read()]
        with open(ch, "wb") as fh:
            fh.write(b"".join(parts))
    except Exception:
        out = [c for c in out if c["name"] != "B10_vpn_chain"]

    # ---- TLS-level tricks (no cert unless stated) -------------------------
    out += [
        dict(name="T01_tls12", tls12=True, desc="TLS1.2 with no client cert"),
        dict(name="T02_tls13_no_cert_default_sni",
             desc="TLS1.3 no cert, SNI=tbox (control)"),
        dict(name="T03_sni_empty", sni="", desc="TLS1.3 no cert, SNI omitted"),
        dict(name="T04_sni_upper", sni="TBOX", desc="SNI=TBOX"),
        dict(name="T05_sni_other", sni="tbox.cybercar.local", desc="SNI=tbox.cybercar.local"),
        dict(name="T06_alpn_h2", alpn=["h2"], desc="ALPN=h2, no cert"),
        dict(name="T07_alpn_http11", alpn=["http/1.1"], desc="ALPN=http/1.1, no cert"),
        dict(name="T08_alpn_acme", alpn=["acme-tls/1"], desc="ALPN=acme-tls/1, no cert"),
        dict(name="T09_tls13_with_valid_shape_cert_and_alpn",
             cert=P("s01_cn_tbox"), key=K("s01_cn_tbox"), alpn=["h2"],
             desc="ALPN=h2 + self-signed cert"),
    ]
    return out


def main():
    regen = "--regen" in sys.argv
    probe_only = "--probe-only" in sys.argv
    os.makedirs(EV, exist_ok=True)
    os.makedirs(PKI, exist_ok=True)
    if not probe_only and (regen or not os.path.exists(os.path.join(PKI, "s01_cn_tbox.pem"))):
        gen()
    elif not os.path.exists(os.path.join(EV, "0102_pki_cert_manifest.txt")):
        gen()

    rows = []
    for c in cases():
        if c.get("cert") and not os.path.exists(c["cert"]):
            rows.append({"case": c["name"], "handshake": "SKIP", "message": "material missing"})
            continue
        r = probe(c)
        rows.append(r)
        print("%-34s %-5s %s" % (r["case"], r["handshake"],
                                 r.get("reason") or r.get("message", "")[:90]))

    with open(os.path.join(EV, "0103_matrix_run.json"), "w", encoding="utf-8") as fh:
        json.dump({"target": "%s:%d" % TARGET, "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                   "rows": rows}, fh, indent=1, ensure_ascii=False)

    lines = ["###### T-BOX 10.230.164.3:8443 client-cert acceptance matrix ######",
             "# generated by 04_SOLVE/tbox-mtls/make_matrix.py",
             "# utc=%s  openssl=%s" % (dt.datetime.now(dt.timezone.utc).isoformat(),
                                       ssl.OPENSSL_VERSION), ""]
    for r in rows:
        lines.append("[%s] %s" % (r["case"], r.get("desc", "")))
        lines.append("    handshake=%s tls=%s alpn=%s elapsed=%ss"
                     % (r.get("handshake"), r.get("tls_version"), r.get("alpn_negotiated"),
                        r.get("elapsed_s")))
        if r.get("handshake") == "OK":
            lines.append("    peer=%s / %s" % (r.get("peer_subject"), r.get("peer_issuer")))
            lines.append("    http=%r" % (r.get("http_head", "")[:300],))
        else:
            lines.append("    reason=%s alert=%s" % (r.get("reason"), r.get("alert_number")))
            lines.append("    message=%s" % r.get("message"))
        lines.append("")
    with open(os.path.join(EV, "0104_matrix_run.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("\n[out] 03_EVIDENCE/tbox-mtls/0103_matrix_run.json")
    print("[out] 03_EVIDENCE/tbox-mtls/0104_matrix_run.txt")


if __name__ == "__main__":
    main()
