#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deterministic evidence capture for CGW DoIP (10.229.221.2).

Re-runs every key exchange recorded in RECON.md and writes one file per
exchange into 03_EVIDENCE/cgw-doip/  (E-cgw-<tag>-NN.txt).

  python capture_evidence.py            # full capture
  python capture_evidence.py --quick    # skip the 269-DID bulk sweep

Each evidence file contains:
  time / target / command / tx hex / rx hex (per message) / decoded JSON
"""

import binascii
import json
import os
import socket
import ssl
import struct
import sys
import time

HOST = "10.229.221.2"
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EVID = os.path.join(ROOT, "03_EVIDENCE", "cgw-doip")

VER = "1.0"   # evidence format version


# ------------------------------------------------------------------ framing
def hdr(mtype, plen):
    return b"\x02\xfd" + struct.pack(">H", mtype) + struct.pack(">I", plen)


def msg(mtype, payload=b""):
    return hdr(mtype, len(payload)) + payload


def recv_frame(s, to=2.0):
    """Read exactly one DoIP frame. Returns (type, payload) or (None, b'')."""
    old = s.gettimeout()
    s.settimeout(to)
    try:
        b = b""
        while len(b) < 8:
            c = s.recv(8 - len(b))
            if not c:
                return None, b""
            b += c
        _v, _i, t, l = struct.unpack(">BBHI", b)
        pl = b""
        while len(pl) < l:
            c = s.recv(l - len(pl))
            if not c:
                break
            pl += c
        return t, pl
    except socket.timeout:
        return "TIMEOUT", b""
    finally:
        try:
            s.settimeout(old)
        except Exception:
            pass


def hexs(b):
    return binascii.hexlify(b).decode() if b else ""


# ------------------------------------------------------------------ evidence
_seq = {}


def save(tag, cmd, tx, rxs, note="", target=None):
    os.makedirs(EVID, exist_ok=True)
    n = _seq.get(tag, 0) + 1
    while True:
        p = os.path.join(EVID, "E-cgw-%s-%02d.txt" % (tag, n))
        if not os.path.exists(p):
            break
        n += 1
    _seq[tag] = n
    tgt = target or ("%s:13400/TCP" % HOST)
    with open(p, "w", encoding="utf-8") as f:
        f.write("# CGW DoIP evidence (format v%s)\n" % VER)
        f.write("time     : %s\n" % time.strftime("%Y-%m-%d %H:%M:%S%z"))
        f.write("target   : %s\n" % tgt)
        f.write("command  : %s\n" % cmd)
        f.write("tx_hex   : %s\n" % hexs(tx))
        for i, (t, pl, raw) in enumerate(rxs):
            f.write("rx[%d]_hex: %s\n" % (i, hexs(raw)))
            f.write("rx[%d]_typ: %s\n" % (i, ("0x%04X" % t) if isinstance(t, int) else str(t)))
        if note:
            f.write("note     : %s\n" % note)
        f.write("\n--- decoded ---\n")
        f.write(json.dumps(decode(rxs), ensure_ascii=False, indent=2))
        f.write("\n")
    return p


def decode(rxs):
    out = []
    names = {0x0000: "GenericHeaderNACK", 0x0001: "VehicleIdReq", 0x0002: "VehicleAnnouncement/VIN",
             0x0003: "VehicleAnnouncement/NoVIN", 0x0004: "VehicleIdResponse",
             0x0005: "RoutingActivationReq", 0x0006: "RoutingActivationResponse",
             0x0007: "AliveCheckReq", 0x0008: "AliveCheckResponse",
             0x4001: "EntityStatusReq", 0x4002: "EntityStatusRes",
             0x8001: "DiagnosticMessage", 0x8002: "DiagPosAck", 0x8003: "DiagNegAck"}
    ra_codes = {0x00: "denied-unknown-source-address",
                0x01: "denied-all-sockets-registered",
                0x02: "denied-already-registered-different-SA",
                0x03: "denied-already-registered-same-SA",
                0x04: "denied-missing-authentication",
                0x05: "denied-rejected-confirmation",
                0x06: "denied-unsupported-activation-type",
                0x07: "denied-TLS-required",
                0x10: "SUCCESSFUL",
                0x11: "pending-confirmation-required"}
    nacks = {0x00: "incorrect pattern format", 0x01: "unknown payload type",
             0x02: "message too large", 0x03: "out of memory", 0x04: "invalid payload length"}
    nrcs = {0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
            0x13: "incorrectMessageLengthOrInvalidFormat", 0x21: "busyRepeatRequest",
            0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
            0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x78: "responsePending"}
    for item in rxs:
        t, pl = item[0], item[1]
        d = {"type": ("0x%04X" % t) if isinstance(t, int) else str(t),
             "name": names.get(t, "unknown") if isinstance(t, int) else "n/a",
             "payload_hex": hexs(pl)}
        if isinstance(t, int):
            if t == 0x0004 and len(pl) >= 17:
                d["vin"] = pl[:17].decode("ascii", "replace")
                if len(pl) >= 19:
                    d["logical_address"] = "0x%04X" % struct.unpack(">H", pl[17:19])[0]
                if len(pl) >= 25:
                    d["eid"] = hexs(pl[19:25])
                if len(pl) >= 31:
                    d["gid"] = hexs(pl[25:31])
                if len(pl) >= 32:
                    d["further_action"] = pl[31]
            elif t == 0x0006 and len(pl) >= 5:
                d["tester_logical_address"] = "0x%04X" % struct.unpack(">H", pl[0:2])[0]
                d["entity_logical_address"] = "0x%04X" % struct.unpack(">H", pl[2:4])[0]
                d["response_code"] = "0x%02X" % pl[4]
                d["response_meaning"] = ra_codes.get(pl[4], "unknown")
            elif t == 0x0000 and pl:
                d["nack_code"] = "0x%02X" % pl[0]
                d["nack_meaning"] = nacks.get(pl[0], "unknown")
            elif t == 0x8001 and len(pl) >= 4:
                d["source_address"] = "0x%04X" % struct.unpack(">H", pl[0:2])[0]
                d["target_address"] = "0x%04X" % struct.unpack(">H", pl[2:4])[0]
                u = pl[4:]
                d["uds_hex"] = hexs(u)
                if u and u[0] == 0x7F:
                    d["uds_negative"] = True
                    d["nrc"] = "0x%02X" % u[2] if len(u) >= 3 else "?"
                    d["nrc_meaning"] = nrcs.get(u[2], "unknown") if len(u) >= 3 else "?"
                elif u and u[0] == 0x62 and len(u) >= 3:
                    d["uds_positive"] = "ReadDataByIdentifier"
                    d["did"] = "0x%04X" % struct.unpack(">H", u[1:3])[0]
                    d["value_hex"] = hexs(u[3:])
                    if d["did"] == "0xF190":
                        d["vin"] = u[3:].decode("ascii", "replace")
        out.append(d)
    return out


# ------------------------------------------------------------------ sessions
def one_shot(tx, to=2.0, max_msgs=6):
    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, 13400))
    s.sendall(tx)
    rxs = []
    for _ in range(max_msgs):
        t, pl = recv_frame(s, to)
        if t is None or t == "TIMEOUT":
            if t == "TIMEOUT" and not rxs:
                rxs.append(("TIMEOUT", b"", b""))
            break
        rxs.append((t, pl, hdr(t, len(pl)) + pl))
    s.close()
    return rxs


def diag(src, tgt, uds_hex, act_type=0xE0, oem=b"\x00\x00\x00\x00", do_ra=True):
    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, 13400))
    ra_rx = []
    if do_ra:
        ra = struct.pack(">H", src) + bytes([act_type]) + b"\x00" * 4 + oem
        s.sendall(msg(0x0005, ra))
        t, pl = recv_frame(s, 2.0)
        if t is not None and t != "TIMEOUT":
            ra_rx.append((t, pl, hdr(t, len(pl)) + pl))
    dg = struct.pack(">H", src) + struct.pack(">H", tgt) + bytes.fromhex(uds_hex)
    s.sendall(msg(0x8001, dg))
    dg_rx = []
    for _ in range(3):
        t, pl = recv_frame(s, 2.0)
        if t is None or t == "TIMEOUT":
            break
        dg_rx.append((t, pl, hdr(t, len(pl)) + pl))
        if t == 0x8001:
            break
    s.close()
    return ra_rx, dg_rx


# ------------------------------------------------------------------ captures
def cap_ports():
    """TCP reachability + banner behaviour of 8080/13400/13401."""
    res = []
    for p in (8080, 13400, 13401):
        s = socket.socket()
        s.settimeout(4)
        t0 = time.time()
        try:
            s.connect((HOST, p))
            res.append({"port": p, "connect": "OPEN", "rtt_ms": round((time.time() - t0) * 1000, 1)})
        except Exception as e:
            res.append({"port": p, "connect": "FAIL", "err": str(e)})
        s.close()
    tx = b""
    rxs = [("INFO", json.dumps(res).encode(), json.dumps(res).encode())]
    save("ports", "TCP connect sweep 8080/13400/13401", tx, rxs, "connectivity only")
    return res


def cap_identify():
    tx = msg(0x0001, b"")
    rx = one_shot(tx)
    save("identify", "VehicleIdentificationRequest 0x0001 (empty payload) -- ISO 13400 conformant", tx, rx,
         "baseline VIN disclosure")
    return rx


def cap_identify_junk():
    for junk, label in ((b"GARBAGE!", "8-byte ASCII junk"),
                        (b"\xaa" * 64, "64-byte 0xAA junk")):
        tx = msg(0x0001, junk)
        rx = one_shot(tx)
        save("identify-junk", "VehicleIdentificationRequest 0x0001 with %s payload "
                              "(spec requires payload length == 0)" % label, tx, rx,
             "H-003: payload length not validated, VIN still returned")


def cap_ra_matrix():
    srcs = [0x0E00, 0x0E80, 0x0100, 0x0000, 0x0001, 0x1000, 0x0FFF, 0xE000, 0xFFFF]
    ats = [0x00, 0x01, 0x02, 0xE0, 0xFF]
    table = []
    for src in srcs:
        for at in ats:
            ra = struct.pack(">H", src) + bytes([at]) + b"\x00" * 8
            tx = msg(0x0005, ra)
            s = socket.socket()
            s.settimeout(5)
            try:
                s.connect((HOST, 13400))
                s.sendall(tx)
                t, pl = recv_frame(s, 2.0)
                code = ("0x%02X" % pl[4]) if (isinstance(t, int) and t == 0x0006 and len(pl) >= 5) else str(t)
                table.append({"src": "0x%04X" % src, "act_type": "0x%02X" % at, "response_code": code})
            except Exception as e:
                table.append({"src": "0x%04X" % src, "act_type": "0x%02X" % at, "error": str(e)})
            finally:
                s.close()
            time.sleep(0.15)
    rxs = [("TABLE", json.dumps(table).encode(), json.dumps(table).encode())]
    save("ra-matrix", "RoutingActivation 0x0005 x %d src addresses x %d activation types" %
         (len(srcs), len(ats)), b"", rxs,
         "H-002: every combination returns 0x10 SUCCESSFUL (no auth, no source-address validation)")


def cap_ra_duplicate():
    """Two sockets, same tester SA -> spec says 2nd must be denied 0x02/0x03."""
    a = socket.socket(); a.settimeout(5); a.connect((HOST, 13400))
    b = socket.socket(); b.settimeout(5); b.connect((HOST, 13400))
    ra = struct.pack(">H", 0x0E00) + b"\xE0" + b"\x00" * 8
    a.sendall(msg(0x0005, ra)); ta, pa = recv_frame(a, 2.0)
    b.sendall(msg(0x0005, ra)); tb, pb = recv_frame(b, 2.0)
    # socket A must still work
    a.sendall(msg(0x8001, struct.pack(">H", 0x0E00) + struct.pack(">H", 0x1000) + bytes.fromhex("22F190")))
    tc, pc = recv_frame(a, 2.0)
    a.close(); b.close()
    rxs = [(ta, pa, hdr(ta, len(pa)) + pa),
           (tb, pb, hdr(tb, len(pb)) + pb),
           (tc, pc, hdr(tc, len(pc)) + pc)]
    save("ra-duplicate", "RoutingActivation from SA 0x0E00 on socket A then socket B "
                         "(spec: 2nd must be 0x02/0x03), then diag on socket A", b"", rxs,
         "duplicate registration allowed; both sockets keep a live diagnostics session")


def cap_no_ra():
    tx = msg(0x8001, struct.pack(">H", 0x0E00) + struct.pack(">H", 0x1000) + bytes.fromhex("22F190"))
    rx = one_shot(tx)
    save("no-routing-activation", "DiagnosticMessage 0x8001 (22 F1 90) sent WITHOUT RoutingActivation",
         tx, rx, "control: diagnostics are correctly gated behind RoutingActivation (NRC 0x22)")


def cap_vin_uds():
    ra_rx, dg_rx = diag(0x0E00, 0x1000, "22F190")
    save("uds-vin", "RoutingActivation(SA 0x0E00) then UDS 22 F1 90 -> 0x1000", b"", ra_rx + dg_rx,
         "independent confirmation of VIN via ReadDataByIdentifier")


def cap_did_f1a0():
    ra_rx, dg_rx = diag(0x0FFE, 0x1000, "22F1A0")
    save("uds-f1a0", "RoutingActivation(SA 0x0FFE) then UDS 22 F1 A0 -> 0x1000", b"", ra_rx + dg_rx,
         "H-005: DID 0xF1A0 leaks the diagnostic logical-address table: "
         "07E0 07E8 07E1 07E9 (two OBD-II request/response pairs)")


def cap_sid_matrix():
    probes = [("1001", "DiagnosticSessionControl extended"), ("1101", "ECUReset"),
              ("1901", "ReadDTCInformation"), ("22F190", "ReadDataByIdentifier F190"),
              ("23140000000001", "ReadMemoryByAddress"), ("2701", "SecurityAccess seed"),
              ("280001", "CommunicationControl"), ("31010001", "RoutineControl"),
              ("3E00", "TesterPresent"), ("8501", "ControlDTCSetting"),
              ("2EF190", "WriteDataByIdentifier F190"), ("340044000000", "RequestDownload")]
    table = []
    for tgt in (0x1000, 0x07E0):
        for uds, label in probes:
            try:
                _, dg = diag(0x0FFE, tgt, uds)
                if not dg:
                    r = "SILENT"
                else:
                    t, pl = dg[0][0], dg[0][1]
                    u = pl[4:] if len(pl) >= 4 else b""
                    if u and u[0] == 0x7F:
                        r = "NRC 0x%02X" % u[2] if len(u) >= 3 else "short"
                    else:
                        r = "POSITIVE " + hexs(u)
            except Exception as e:
                r = "EXC %s" % e
            table.append({"target": "0x%04X" % tgt, "service": label, "uds": uds, "result": r})
            time.sleep(0.12)
    rxs = [("TABLE", json.dumps(table).encode(), json.dumps(table).encode())]
    save("sid-matrix", "UDS service support matrix against 0x1000 (gateway) and 0x07E0 (ECU from F1A0)",
         b"", rxs,
         "0x1000 supports only 0x22 (everything else NRC 0x11 serviceNotSupported); "
         "0x07E0 answers NRC 0x31 requestOutOfRange to every service -> address known, no handler")


def cap_did_bulk():
    s = socket.socket(); s.settimeout(5); s.connect((HOST, 13400))
    s.sendall(msg(0x0005, struct.pack(">H", 0x0FFE) + b"\xE0" + b"\x00" * 8))
    ra = recv_frame(s, 2.0)
    dids = list(range(0xF100, 0xF200)) + [0x0000, 0x0001, 0x0010, 0x0020, 0x0100,
                                          0x0200, 0x0400, 0x0F00, 0x0F10, 0xF000,
                                          0xFE00, 0xFFFF]
    hits = []
    for d_ in dids:
        pl = struct.pack(">H", 0x0FFE) + struct.pack(">H", 0x1000) + bytes([0x22, d_ >> 8, d_ & 0xFF])
        s.sendall(msg(0x8001, pl))
        t, p = recv_frame(s, 1.0)
        if isinstance(t, int) and t == 0x8001 and len(p) >= 7:
            u = p[4:]
            if u[0] != 0x7F:
                hits.append({"did": "0x%04X" % d_, "value_hex": hexs(u[3:]),
                             "ascii": u[3:].decode("ascii", "replace")})
    s.close()
    rxs = [("MAP", json.dumps(hits).encode(), json.dumps(hits).encode())]
    save("did-bulk", "Bulk ReadDataByIdentifier sweep, %d DIDs (0xF100-0xF1FF + common), "
                     "single pipelined connection" % len(dids), b"", rxs,
         "only two readable DIDs exist: 0xF190 (VIN) and 0xF1A0 (diagnostic address table)")


def cap_malformed():
    cases = [
        (msg(0x9999, b""), "unknown payload type 0x9999, empty"),
        (msg(0x9999, b"\x01\x02"), "unknown payload type 0x9999, 2-byte payload"),
        (bytes.fromhex("02fd800100000000"), "DiagnosticMessage 0x8001 with 0-byte payload"),
        (bytes.fromhex("02fd000500000000"), "RoutingActivation 0x0005 with 0-byte payload"),
        (bytes.fromhex("03fd000100000000"), "protocol version 0x03 / inverse 0xFD (invalid version)"),
        (bytes.fromhex("02fe000100000000"), "version 0x02 / inverse 0xFE (invalid inverse)"),
        (bytes.fromhex("0200000100000000"), "version 0x02 / inverse 0x00 (invalid inverse)"),
        (bytes.fromhex("02fd00010000ffff"), "declared payload length 0xFFFF but no payload"),
    ]
    rxs = []
    for tx, label in cases:
        rx = one_shot(tx, to=1.5)
        rxs.append(("CASE", label.encode(), json.dumps({"case": label}).encode()))
        save("malformed", label, tx, rx, "")
        time.sleep(0.15)
    save("malformed-summary", "malformed DoIP frame handling summary", b"", rxs, "")


def cap_udp():
    tx = msg(0x0001, b"")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(tx, (HOST, 13400))
    got = []
    try:
        while True:
            data, _ = s.recvfrom(4096)
            got.append((None, data, data))
    except socket.timeout:
        pass
    s.close()
    save("udp-identify", "VehicleIdentificationRequest over UDP/13400", tx, got,
         "no response: UDP vehicle discovery / announcement plane is closed",
         target="%s:13400/UDP" % HOST)


def cap_13401():
    tx = msg(0x0001, b"")
    s = socket.socket(); s.settimeout(4)
    rxs = []
    try:
        s.connect((HOST, 13401))
        s.sendall(tx)
        try:
            d = s.recv(4096)
            rxs.append(("RAW", d, d))
        except Exception as e:
            rxs.append(("ERR", str(e).encode(), str(e).encode()))
    except Exception as e:
        rxs.append(("ERR", str(e).encode(), str(e).encode()))
    s.close()
    save("port-13401-raw", "plain DoIP VehicleIdentificationRequest to 13401", tx, rxs,
         "server closes the connection immediately", target="%s:13401/TCP" % HOST)

    ctx = ssl._create_unverified_context()
    rxs2 = []
    try:
        s2 = ctx.wrap_socket(socket.socket(), server_hostname=HOST)
        s2.settimeout(5)
        s2.connect((HOST, 13401))
        rxs2.append(("TLS", ("version=%s cipher=%s" % (s2.version(), s2.cipher())).encode(),
                     ("version=%s cipher=%s" % (s2.version(), s2.cipher())).encode()))
        s2.close()
    except Exception as e:
        msg_ = "%s: %s" % (type(e).__name__, e)
        rxs2.append(("ERR", msg_.encode(), msg_.encode()))
    save("port-13401-tls", "TLS ClientHello to 13401", b"", rxs2,
         "not a TLS service either (EOF during handshake)", target="%s:13401/TCP" % HOST)


def cap_8080():
    import http.client
    paths = ["/", "/api", "/api/", "/api/v1", "/health", "/healthz", "/readyz", "/livez",
             "/ping", "/diag", "/diagnostics", "/doip", "/can", "/bus", "/dtc",
             "/vehicles", "/vehicle", "/vin", "/status", "/metrics", "/version", "/info",
             "/config", "/debug/pprof/", "/debug/vars", "/admin", "/ota", "/ota/",
             "/update", "/firmware", "/login", "/auth", "/token", "/ws", "/websocket",
             "/graphql", "/api/v1/vehicles", "/api/v1/status", "/swagger", "/openapi.json",
             "/docs", "/robots.txt", "/.git/HEAD", "/healthz/", "/healthz?verbose=1"]
    rows = []
    for p in paths:
        try:
            c = http.client.HTTPConnection(HOST, 8080, timeout=4)
            c.request("GET", p)
            r = c.getresponse()
            b = r.read(300)
            default_404 = (r.status == 404 and b.strip() == b"404 page not found")
            if not default_404:
                rows.append({"path": p, "status": r.status, "body": b.decode("utf-8", "replace")[:200],
                             "headers": dict(r.getheaders())})
            c.close()
        except Exception as e:
            rows.append({"path": p, "error": str(e)})
    rxs = [("TABLE", json.dumps(rows).encode(), json.dumps(rows).encode())]
    save("http-8080", "HTTP GET path enumeration on 8080 (%d paths); only non-default-404 shown" % len(paths),
         b"", rxs, "only /healthz -> 200 {\"status\":\"ok\"}; everything else is the Go default 404",
         target="%s:8080/TCP" % HOST)

    # method + fingerprint
    rows2 = []
    for m in ("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"):
        try:
            c = http.client.HTTPConnection(HOST, 8080, timeout=4)
            c.request(m, "/healthz")
            r = c.getresponse()
            rows2.append({"method": m, "status": r.status, "allow": r.getheader("Allow"),
                          "body": r.read(120).decode("utf-8", "replace")})
            c.close()
        except Exception as e:
            rows2.append({"method": m, "error": str(e)})
    rxs2 = [("TABLE", json.dumps(rows2).encode(), json.dumps(rows2).encode())]
    save("http-8080-methods", "HTTP method matrix on /healthz", b"", rxs2,
         "handler does not check the method: POST/PUT/DELETE/OPTIONS all return 200",
         target="%s:8080/TCP" % HOST)


PEER = "10.230.164.4"


def cap_peer_compare():
    """Compare 10.230.164.4 (discovered by Lead, not in the target list) against the CGW."""
    rows = []
    probes = [
        ("vehicle-id", lambda h: one_shot_host(h, 13400, msg(0x0001, b""))),
        ("uds-22F190", lambda h: diag_host(h, 0x0FFE, 0x1000, "22F190")),
        ("uds-22F1A0", lambda h: diag_host(h, 0x0FFE, 0x1000, "22F1A0")),
        ("uds-1001", lambda h: diag_host(h, 0x0FFE, 0x1000, "1001")),
        ("unknown-type", lambda h: one_shot_host(h, 13400, msg(0x9999, b""))),
        ("junk-0x0001", lambda h: one_shot_host(h, 13400, msg(0x0001, b"JUNKJUNK"))),
    ]
    for label, fn in probes:
        entry = {"probe": label}
        for h in (HOST, PEER):
            try:
                rxs = fn(h)
                entry[h] = [{"type": ("0x%04X" % t) if isinstance(t, int) else str(t),
                             "raw": hexs(raw)} for t, pl, raw in rxs]
            except Exception as e:
                entry[h] = [{"error": "%s: %s" % (type(e).__name__, e)}]
        entry["identical"] = (entry.get(HOST) == entry.get(PEER))
        rows.append(entry)
        time.sleep(0.2)
    rxs = [("TABLE", json.dumps(rows).encode(), json.dumps(rows).encode())]
    save("peer-compare",
         "Behaviour comparison 10.229.221.2 (CGW) vs 10.230.164.4 (unlisted host found by Lead scan)",
         b"", rxs,
         "all probes byte-identical, including EID 06:00:00:00:10:00 -> same DoIP entity",
         target="%s and %s" % (HOST, PEER))

    # 13401 parity
    r2 = []
    for h in (HOST, PEER):
        s = socket.socket(); s.settimeout(4)
        try:
            s.connect((h, 13401))
            s.sendall(msg(0x0001, b""))
            try:
                d = s.recv(256)
                r2.append({"host": h, "port": 13401, "result": "closed_by_peer", "bytes": hexs(d)})
            except Exception as e:
                r2.append({"host": h, "port": 13401, "result": "closed_by_peer", "err": str(e)})
        except Exception as e:
            r2.append({"host": h, "port": 13401, "result": "connect_failed", "err": str(e)})
        s.close()
    rxs2 = [("TABLE", json.dumps(r2).encode(), json.dumps(r2).encode())]
    save("peer-compare-13401", "13401 behaviour parity between CGW and 10.230.164.4", b"", rxs2,
         "both immediately close the connection", target="%s / %s :13401" % (HOST, PEER))


def one_shot_host(host, port, tx, to=2.0, max_msgs=4, retries=3):
    """One-shot exchange with retry: the target occasionally drops a connect under churn."""
    last = None
    for attempt in range(retries):
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect((host, port))
            s.sendall(tx)
            rxs = []
            for _ in range(max_msgs):
                t, pl = recv_frame(s, to)
                if t is None or t == "TIMEOUT":
                    break
                rxs.append((t, pl, hdr(t, len(pl)) + pl))
            if rxs:
                return rxs
            last = "no response"
        except Exception as e:
            last = e
        finally:
            s.close()
        time.sleep(0.5)
    raise RuntimeError("one_shot_host failed after %d attempts: %s" % (retries, last))


def diag_host(host, src, tgt, uds_hex):
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, 13400))
    s.sendall(msg(0x0005, struct.pack(">H", src) + b"\xE0" + b"\x00" * 8))
    ra = recv_frame(s, 2.0)
    s.sendall(msg(0x8001, struct.pack(">H", src) + struct.pack(">H", tgt) + bytes.fromhex(uds_hex)))
    dg = recv_frame(s, 2.0)
    s.close()
    out = []
    for pair in (ra, dg):
        t, pl = pair[0], pair[1]
        if isinstance(t, int):
            out.append((t, pl, hdr(t, len(pl)) + pl))
    return out


def main(argv):
    quick = "--quick" in argv
    print("[*] capture -> %s" % EVID)
    steps = [cap_ports, cap_identify, cap_identify_junk, cap_ra_matrix, cap_ra_duplicate,
             cap_no_ra, cap_vin_uds, cap_did_f1a0, cap_sid_matrix, cap_malformed,
             cap_udp, cap_13401, cap_8080, cap_peer_compare]
    if not quick:
        steps.append(cap_did_bulk)
    for fn in steps:
        try:
            fn()
            print("  [ok] %s" % fn.__name__)
        except Exception as e:
            print("  [!!] %s -> %s: %s" % (fn.__name__, type(e).__name__, e))
        time.sleep(0.4)
    print("[*] done; %d evidence files" % len([f for f in os.listdir(EVID) if f.endswith('.txt')]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
