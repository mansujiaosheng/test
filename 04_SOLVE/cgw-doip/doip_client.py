#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CGW DoIP / ISO 13400-2 client  --  target 10.229.221.2:13400 (and 13401)

Pure stdlib. No third-party packages.

Sub-commands
------------
  identify                      Vehicle Identification Request (0x0001) -> 0x0004
  announce                      Wait for Vehicle Announcement (0x0002/0x0003) as a listener
  routing-activation            RoutingActivation 0x0005 -> 0x0006  (enumerates src addr / act type)
  uds                           RoutingActivation then UDS over 0x8001 (default 22 F1 90)
  raw                           Send an arbitrary DoIP message, hex in / hex out
  udp-identify                  Vehicle Identification Request over UDP 13400
  tls-probe                      Probe 13401 as TLS (DoIP over TLS)
  --self-test                   Parse the known capture offline; no network needed.

Examples
--------
  python doip_client.py identify
  python doip_client.py identify --port 13401
  python doip_client.py routing-activation
  python doip_client.py uds --src 0x0E00 --target 0x1000 --uds 22F190
  python doip_client.py uds --uds 22F187          # spare part / diagnostic address probes
  python doip_client.py raw --type 0x0001 --payload ''
  python doip_client.py udp-identify
  python doip_client.py --self-test

Every exchange appends one record to the evidence directory:
  03_EVIDENCE/cgw-doip/E-cgw-<tag>-<NN>.txt
Record format:
   time, command, TX hex, RX hex, decoded summary
"""

import argparse
import binascii
import os
import socket
import struct
import sys
import time

DEFAULT_HOST = "10.229.221.2"
DEFAULT_PORT = 13400

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EVID_DIR = os.path.join(ROOT, "03_EVIDENCE", "cgw-doip")

# ---------------------------------------------------------------- DoIP payload types
T_VEHICLE_ID_REQ = 0x0001
T_VEHICLE_ANN_VC = 0x0002   # with VIN
T_VEHICLE_ANN_NE = 0x0003   # without VIN
T_DIAG_MSG = 0x8001
T_DIAG_ACK = 0x8002
T_DIAG_NAK = 0x8003
T_VEHICLE_ID_RES = 0x0004
T_ROUTING_ACT_REQ = 0x0005
T_ROUTING_ACT_RES = 0x0006
T_ALIVE_CHECK_REQ = 0x0007
T_ALIVE_CHECK_RES = 0x0008
T_DOIP_ENTITY_STATUS_REQ = 0x4001
T_DOIP_ENTITY_STATUS_RES = 0x4002
T_DIAG_POWER_MODE_REQ = 0x4003
T_DIAG_POWER_MODE_RES = 0x4004

TYPE_NAME = {
    0x0000: "GenericDoIPHeaderNegativeAcknowledge",
    T_VEHICLE_ID_REQ: "VehicleIdentificationRequest",
    T_VEHICLE_ANN_VC: "VehicleAnnouncement/VIN",
    T_VEHICLE_ANN_NE: "VehicleAnnouncement/NoVIN",
    T_VEHICLE_ID_RES: "VehicleIdentificationResponse",
    T_ROUTING_ACT_REQ: "RoutingActivationRequest",
    T_ROUTING_ACT_RES: "RoutingActivationResponse",
    T_ALIVE_CHECK_REQ: "AliveCheckRequest",
    T_ALIVE_CHECK_RES: "AliveCheckResponse",
    T_DIAG_MSG: "DiagnosticMessage",
    T_DIAG_ACK: "DiagnosticMessagePositiveAck",
    T_DIAG_NAK: "DiagnosticMessageNegativeAck",
    T_DOIP_ENTITY_STATUS_REQ: "DoIPEntityStatusRequest",
    T_DOIP_ENTITY_STATUS_RES: "DoIPEntityStatusResponse",
}

# RoutingActivation response codes (ISO 13400-2 Table 47)
RA_CODE = {
    0x00: "Routing activation denied - unknown source address",
    0x01: "Routing activation denied - all sockets registered",
    0x02: "Routing activation denied - source address already registered (different SA)",
    0x03: "Routing activation denied - source address already registered (same SA)",
    0x04: "Routing activation denied - missing authentication",
    0x05: "Routing activation denied - rejected confirmation",
    0x06: "Routing activation denied - unsupported routing activation type",
    0x07: "Routing activation denied - encrypted TLS required",
    0x10: "Routing activation successful",
    0x11: "Routing activation pending - confirmation required",
}

# UDS negative response codes
UDS_NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x37: "requiredTimeDelayNotExpired",
    0x78: "responsePending",
    0x7F: "serviceNotSupportedInActiveSession",
}


# ---------------------------------------------------------------- framing
def build(msg_type, payload=b""):
    """8-byte DoIP generic header: 02 FD | type(2B BE) | len(4B BE) | payload."""
    return b"\x02\xfd" + struct.pack(">H", msg_type) + struct.pack(">I", len(payload)) + payload


def recv_msg(sock):
    """Read exactly one DoIP message (header then declared payload). Returns (type, payload, raw)."""
    hdr = _recv_exact(sock, 8)
    if not hdr:
        return None, None, b""
    if len(hdr) < 8:
        return None, None, hdr
    ver, inv, mtype, plen = struct.unpack(">BBHI", hdr)
    payload = _recv_exact(sock, plen) if plen else b""
    return mtype, payload, hdr + (payload or b"")


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def hexs(b):
    return binascii.hexlify(b).decode() if b else ""


# ---------------------------------------------------------------- decoding
def decode_vehicle_id_res(payload):
    """0x0004: VIN(17) | LogicalAddress(2) | EID(6) | GID(6) | FurtherAction(1)"""
    d = {}
    if len(payload) >= 17:
        d["vin_raw"] = payload[:17]
        try:
            d["vin"] = payload[:17].decode("ascii", "replace")
        except Exception:
            d["vin"] = repr(payload[:17])
    if len(payload) >= 19:
        d["logical_address"] = struct.unpack(">H", payload[17:19])[0]
    if len(payload) >= 25:
        d["eid"] = payload[19:25]
    if len(payload) >= 31:
        d["gid"] = payload[25:31]
    if len(payload) >= 32:
        d["further_action"] = payload[31]
    d["declared_len"] = len(payload)
    return d


def decode_routing_act_res(payload):
    """0x0006: testerLA(2) | entityLA(2) | code(1) | reserved(4) | OEM(4)"""
    d = {}
    if len(payload) >= 2:
        d["tester_logical_address"] = struct.unpack(">H", payload[0:2])[0]
    if len(payload) >= 4:
        d["entity_logical_address"] = struct.unpack(">H", payload[2:4])[0]
    if len(payload) >= 5:
        d["response_code"] = payload[4]
        d["response_meaning"] = RA_CODE.get(payload[4], "unknown")
    if len(payload) >= 13:
        d["oem_specific"] = payload[9:13]
    d["declared_len"] = len(payload)
    return d


def decode_diag_ack(payload):
    """0x8002/0x8003: sourceLA(2) | targetLA(2) | ackcode(1) [+ previousDiagData(4)]"""
    d = {}
    if len(payload) >= 4:
        d["source_address"] = struct.unpack(">H", payload[0:2])[0]
        d["target_address"] = struct.unpack(">H", payload[2:4])[0]
    if len(payload) >= 5:
        d["ack_code"] = payload[4]
    d["declared_len"] = len(payload)
    return d


DIAG_ACK_CODE = {
    0x00: "routing confirmation ack",
    0x01: "no ack - invalid source address",
    0x02: "no ack - unknown target address",
    0x03: "no ack - diagnostic message too large",
    0x04: "no ack - out of memory",
    0x05: "no ack - target unreachable",
    0x06: "no ack - unknown network",
    0x07: "no ack - transport protocol error",
}

# Generic DoIP header NACK codes (message type 0x0000)
GENERIC_NACK = {
    0x00: "incorrect pattern format",
    0x01: "unknown payload type",
    0x02: "message too large",
    0x03: "out of memory",
    0x04: "invalid payload length",
}


def decode_uds(data):
    """Minimal UDS response decoder."""
    d = {}
    if not data:
        d["error"] = "empty"
        return d
    if data[0] == 0x7F and len(data) >= 3:
        d["negative"] = True
        d["request_sid"] = data[1]
        d["nrc"] = data[2]
        d["nrc_meaning"] = UDS_NRC.get(data[2], "unknown")
        return d
    d["positive"] = True
    sid = data[0]
    d["sid"] = sid
    if sid == 0x62 and len(data) >= 3:   # ReadDataByIdentifier positive
        did = struct.unpack(">H", data[1:3])[0]
        d["did"] = did
        body = data[3:]
        d["value_hex"] = hexs(body)
        if did == 0xF190:
            try:
                d["vin"] = body.decode("ascii", "replace")
            except Exception:
                pass
        else:
            try:
                txt = body.decode("ascii")
                if txt.isprintable():
                    d["value_ascii"] = txt
            except Exception:
                pass
    return d


def summarize(raw_list):
    """Human summary of the decoded DoIP messages in the list."""
    out = []
    for mtype, payload, raw in raw_list:
        if mtype is None:
            out.append({"type": None, "note": "no/short header", "raw": hexs(raw)})
            continue
        item = {"type": "0x%04X" % mtype, "name": TYPE_NAME.get(mtype, "unknown"), "raw": hexs(raw)}
        if mtype == T_VEHICLE_ID_RES:
            item.update(decode_vehicle_id_res(payload))
        elif mtype == T_ROUTING_ACT_RES:
            item.update(decode_routing_act_res(payload))
        elif mtype in (T_DIAG_ACK, T_DIAG_NAK):
            item.update(decode_diag_ack(payload))
        elif mtype == 0x0000:
            item["nack_code"] = payload[0] if payload else None
            item["nack_meaning"] = GENERIC_NACK.get(payload[0]) if payload else None
        elif mtype == T_DIAG_MSG:
            # sourceLA(2) targetLA(2) then UDS
            if len(payload) >= 4:
                item["source_address"] = struct.unpack(">H", payload[0:2])[0]
                item["target_address"] = struct.unpack(">H", payload[2:4])[0]
                item["uds"] = decode_uds(payload[4:])
        out.append(item)
    return out


# ---------------------------------------------------------------- evidence
_counter = {}


def write_evidence(tag, command, tx, rx_list, host, port, extra=""):
    os.makedirs(EVID_DIR, exist_ok=True)
    _counter[tag] = _counter.get(tag, 0) + 1
    n = _counter[tag]
    # pick up existing numbering so reruns do not overwrite
    while True:
        path = os.path.join(EVID_DIR, "E-cgw-%s-%02d.txt" % (tag, n))
        if not os.path.exists(path):
            break
        n += 1
    with open(path, "w", encoding="utf-8") as f:
        f.write("# CGW DoIP evidence\n")
        f.write("time      : %s\n" % time.strftime("%Y-%m-%d %H:%M:%S%z"))
        f.write("target    : %s:%d\n" % (host, port))
        f.write("command   : %s\n" % command)
        f.write("tx_hex    : %s\n" % hexs(tx))
        f.write("tx_len    : %d\n" % len(tx))
        if len(rx_list) == 1:
            f.write("rx_hex    : %s\n" % hexs(rx_list[0][2]))
            f.write("rx_len    : %d\n" % len(rx_list[0][2]))
        else:
            for i, (mt, pl, raw) in enumerate(rx_list):
                f.write("rx[%d]_hex : %s\n" % (i, hexs(raw)))
        if extra:
            f.write("note      : %s\n" % extra)
        f.write("\n--- decoded ---\n")
        import json
        f.write(json.dumps(summarize(rx_list), ensure_ascii=False, indent=2,
                           default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
        f.write("\n")
    print("[evidence] %s" % path)
    return path


# ---------------------------------------------------------------- transports
def tcp_exchange(host, port, tx, read_all=True, timeout=5.0, max_msgs=8, idle=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    s.sendall(tx)
    msgs = []
    s.settimeout(idle)
    while len(msgs) < max_msgs:
        try:
            mt, pl, raw = recv_msg(s)
        except socket.timeout:
            break
        if mt is None:
            break
        msgs.append((mt, pl, raw))
        if not read_all:
            break
    try:
        s.close()
    except Exception:
        pass
    return msgs


def udp_exchange(host, port, tx, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(tx, (host, port))
    msgs = []
    try:
        while True:
            data, _addr = s.recvfrom(4096)
            if len(data) >= 8:
                ver, inv, mt, plen = struct.unpack(">BBHI", data[:8])
                msgs.append((mt, data[8:8 + plen], data))
            else:
                msgs.append((None, None, data))
    except socket.timeout:
        pass
    s.close()
    return msgs


# ---------------------------------------------------------------- high level
def do_identify(host, port, udp=False):
    tx = build(T_VEHICLE_ID_REQ, b"")
    msgs = udp_exchange(host, port, tx) if udp else tcp_exchange(host, port, tx)
    tag = "udp-identify" if udp else "identify"
    write_evidence(tag, "vehicle identification request (0x0001, empty payload)",
                   tx, msgs, host, port,
                   "UDP" if udp else "TCP")
    return msgs


def do_routing_activation(host, port, src, act_type, oem=b"\x00\x00\x00\x00", keep_open=False):
    payload = struct.pack(">H", src) + bytes([act_type]) + b"\x00" * 4 + oem
    tx = build(T_ROUTING_ACT_REQ, payload)
    if keep_open:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(tx)
        s.settimeout(0.8)
        msgs = []
        for _ in range(4):
            try:
                mt, pl, raw = recv_msg(s)
            except socket.timeout:
                break
            if mt is None:
                break
            msgs.append((mt, pl, raw))
        return msgs, s
    msgs = tcp_exchange(host, port, tx)
    return msgs, None


def do_uds(host, port, src, target, uds_bytes, act_type=0xE0, read_alive=True):
    """RoutingActivation, then DiagnosticMessage 0x8001, collect ACK + UDS response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))

    ra_pl = struct.pack(">H", src) + bytes([act_type]) + b"\x00" * 4 + b"\x00" * 4
    ra_tx = build(T_ROUTING_ACT_REQ, ra_pl)
    s.sendall(ra_tx)
    s.settimeout(1.5)
    ra_msgs = []
    for _ in range(3):
        try:
            mt, pl, raw = recv_msg(s)
        except socket.timeout:
            break
        if mt is None:
            break
        ra_msgs.append((mt, pl, raw))
        if mt == T_ROUTING_ACT_RES:
            break

    ra_ok = any(m[0] == T_ROUTING_ACT_RES and len(m[1]) >= 5 and m[1][4] == 0x10
                for m in ra_msgs)

    diag_pl = struct.pack(">H", src) + struct.pack(">H", target) + uds_bytes
    diag_tx = build(T_DIAG_MSG, diag_pl)
    # send regardless; record whether RA succeeded
    s.sendall(diag_tx)
    s.settimeout(2.0)
    diag_msgs = []
    for _ in range(10):
        try:
            mt, pl, raw = recv_msg(s)
        except socket.timeout:
            break
        if mt is None:
            break
        diag_msgs.append((mt, pl, raw))
        if mt == T_DIAG_MSG and len(pl) >= 4:
            # stop once we have a non-pending UDS response
            if not (pl[4] == 0x7F and len(pl) >= 7 and pl[6] == 0x78):
                break
    s.close()

    msgs = ra_msgs + diag_msgs
    note = "RA src=0x%04X type=0x%02X target=0x%04X ok=%s ; UDS=%s" % (
        src, act_type, target, ra_ok, hexs(uds_bytes))
    write_evidence("uds", note, ra_tx + diag_tx, msgs, host, port,
                   "tx is RA||DIAG concatenated")
    out = {"ra_ok": ra_ok, "ra": ra_msgs, "diag": diag_msgs}
    return out


# ---------------------------------------------------------------- self test
KNOWN_IDENTIFY_RX = (
    "02fd0004000000" "21"
    "4356364646353246454539454444443836"
    "1000" "060000001000" "000000000000" "0000"
)


def self_test():
    global KNOWN_IDENTIFY_RX
    raw = bytes.fromhex(KNOWN_IDENTIFY_RX.replace(" ", ""))
    print("[self-test] captured RX length =", len(raw), "bytes")
    ver, inv, mt, plen = struct.unpack(">BBHI", raw[:8])
    assert ver == 0x02 and inv == 0xFD, "bad protocol version/inverse"
    assert mt == T_VEHICLE_ID_RES, "bad message type: 0x%04X" % mt
    payload = raw[8:8 + plen]
    assert len(payload) == plen, "declared len %d != actual %d" % (plen, len(payload))
    d = decode_vehicle_id_res(payload)
    print("[self-test] decoded:", {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d.items()})
    assert d.get("vin") == "CV6FF52FEE9EDDD86", "VIN mismatch: %r" % d.get("vin")
    assert d["logical_address"] == 0x1000
    assert d["further_action"] == 0x0000

    # framing round trip
    tx = build(T_VEHICLE_ID_REQ, b"")
    assert tx == bytes.fromhex("02fd000100000000"), tx.hex()
    assert len(tx) == 8

    # UDS 62 F1 90 decode
    u = decode_uds(bytes.fromhex("62f190" + "4356364646353246454539454444443836"))
    assert u.get("vin") == "CV6FF52FEE9EDDD86", u

    # RA response decode (success)
    ra = decode_routing_act_res(bytes.fromhex("0e00" "1000" "10" "00000000" "00000000"))
    assert ra["response_code"] == 0x10 and ra["entity_logical_address"] == 0x1000

    # negative response decode
    n = decode_uds(bytes.fromhex("7f2231"))
    assert n.get("nrc") == 0x31 and n.get("nrc_meaning") == "requestOutOfRange"

    print("[self-test] ALL PASS")
    return 0


# ---------------------------------------------------------------- main
def main(argv):
    ap = argparse.ArgumentParser(description="CGW DoIP / ISO 13400 client",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("identify")
    sub.add_parser("udp-identify")
    sub.add_parser("announce")

    ra = sub.add_parser("routing-activation")
    ra.add_argument("--src", type=lambda x: int(x, 0), default=None,
                    help="source address; omit to sweep defaults")
    ra.add_argument("--act-type", type=lambda x: int(x, 0), default=None)

    u = sub.add_parser("uds")
    u.add_argument("--src", type=lambda x: int(x, 0), default=0x0E00)
    u.add_argument("--target", type=lambda x: int(x, 0), default=0x1000)
    u.add_argument("--uds", default="22F190", help="UDS bytes as hex, default 22F190")
    u.add_argument("--act-type", type=lambda x: int(x, 0), default=0xE0)

    r = sub.add_parser("raw")
    r.add_argument("--type", type=lambda x: int(x, 0), required=True)
    r.add_argument("--payload", default="", help="payload hex")

    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    host, port = args.host, args.port

    if args.cmd == "identify":
        msgs = do_identify(host, port, udp=False)
    elif args.cmd == "udp-identify":
        msgs = do_identify(host, port, udp=True)
    elif args.cmd == "announce":
        print("[*] listening for announcements on TCP %s:%d for 10s" % (host, port))
        tx = build(T_VEHICLE_ID_REQ, b"")
        msgs = tcp_exchange(host, port, tx, timeout=10.0, max_msgs=4, idle=9.0)
    elif args.cmd == "routing-activation":
        srcs = [args.src] if args.src is not None else [0x0E00, 0x0E80, 0x0100, 0x0E01, 0x1000]
        ats = [args.act_type] if args.act_type is not None else [0x00, 0x01, 0xE0]
        allm = []
        for src in srcs:
            for at in ats:
                print("\n=== RA src=0x%04X act_type=0x%02X ===" % (src, at))
                m, _ = do_routing_activation(host, port, src, at)
                for item in summarize(m):
                    print("   ", item)
                allm += m
        msgs = allm
    elif args.cmd == "uds":
        if args.port != DEFAULT_PORT:
            print("[*] note: port %d" % args.port)
        res = do_uds(host, port, args.src, args.target, bytes.fromhex(args.uds),
                     act_type=args.act_type)
        print("\n--- routing activation ---")
        for item in summarize(res["ra"]):
            print("   ", item)
        print("\n--- diagnostic ---")
        for item in summarize(res["diag"]):
            print("   ", item)
        return 0
    elif args.cmd == "raw":
        tx = build(args.type, bytes.fromhex(args.payload))
        msgs = tcp_exchange(host, port, tx)
        write_evidence("raw", "raw type=0x%04X payload=%s" % (args.type, args.payload),
                       tx, msgs, host, port)
    else:
        ap.print_help()
        return 2

    print("\n=== decoded ===")
    import json
    print(json.dumps(summarize(msgs), ensure_ascii=False, indent=2,
                     default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
