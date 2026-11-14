#!/usr/bin/env python3
"""Well-formed UDS probe set.

Discovery that motivated this: the gateway answers NRC 0x11 (serviceNotSupported)
for a *malformed* request (`22 00`, 2 bytes) while a well-formed but unknown DID
(`22 F1 87`) gives NRC 0x31. So a sweep that sends `<SID> 00` labels almost every
service "unsupported" as an artefact of bad framing.

Each probe here is a syntactically valid request for its service.
"""
import json, os, binascii, time
from cli import Cli, pfmt

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wellformed.jsonl")


def probes():
    P = []
    # --- session control: every session type the standard allows (+ OEM range) ---
    for s in list(range(0x01, 0x06)) + [0x40, 0x41, 0x42, 0x50, 0x60, 0x70, 0x7E, 0x7F]:
        P.append(("10_%02X" % s, bytes([0x10, s]), "session control sessionType=0x%02X" % s))
    # --- ECU reset ---
    for s in (0x01, 0x02, 0x03, 0x04, 0x05, 0x81, 0x82, 0x83):
        P.append(("11_%02X" % s, bytes([0x11, s]), "ECUReset type=0x%02X" % s))
    # --- clear DTC ---
    P.append(("14_FFFFFF", bytes.fromhex("14FFFFFF"), "ClearDTC group=0xFFFFFF"))
    P.append(("14_000000", bytes.fromhex("14000000"), "ClearDTC group=0x000000"))
    # --- read DTC ---
    for s in (0x01, 0x02, 0x03, 0x04, 0x06, 0x0A, 0x14, 0x15, 0x42):  # 0x42 = WWH-OBD
        P.append(("19_%02X" % s, bytes([0x19, s]), "ReadDTCInformation sub=0x%02X" % s))
    # --- security access: request seed for every odd level ---
    for lvl in range(0x01, 0x22, 2):
        P.append(("27_%02X" % lvl, bytes([0x27, lvl]), "SecurityAccess requestSeed level=0x%02X" % lvl))
    # --- communication control ---
    P.append(("28_0001", bytes.fromhex("280001"), "CommunicationControl disableRxTx type=01"))
    P.append(("28_0301", bytes.fromhex("280301"), "CommunicationControl enableRxTx"))
    # --- write/read DID ---
    P.append(("2E_F190", bytes.fromhex("2EF190") + b"\x00" * 17, "WriteDataByIdentifier F190 (17 bytes)"))
    P.append(("2F_F190_03", bytes.fromhex("2FF19003"), "IOControl F190 controlParameter=03"))
    # --- routine control: start/stop/results for a spread of routine ids ---
    for rid in (0x0001, 0x0002, 0x0202, 0x0203, 0x0262, 0xFF00, 0xFF01, 0xFF02,
                0xEF00, 0xE200, 0x0100, 0x0401, 0x0601, 0x0801):
        P.append(("31_01_%04X" % rid, bytes([0x31, 0x01]) + rid.to_bytes(2, "big"),
                  "RoutineControl start routine=0x%04X" % rid))
    P.append(("31_03_FF00", bytes.fromhex("3103FF00"), "RoutineControl requestResults 0xFF00"))
    # --- request download / transfer / exit ---
    P.append(("34_0044_00000000_00100000", bytes.fromhex("3400440000000000100000"),
              "RequestDownload ALFID=0x44 addr=0x00000000 len=0x00100000"))
    P.append(("34_0044_08000000_0010000", bytes.fromhex("34004408000000001000"),
              "RequestDownload addr=0x08000000 len=0x001000"))
    P.append(("34_1044_00000000_00100000", bytes.fromhex("3410440000000000100000"),
              "RequestDownload compression/encryption bit set"))
    P.append(("34_0044_FFFFFFFF_FFFFFFFF", bytes.fromhex("340044FFFFFFFFFFFFFFFF"),
              "RequestDownload max addr/len"))
    P.append(("36_01_00", bytes.fromhex("360100"), "TransferData block=1 1 byte"))
    P.append(("37", bytes.fromhex("37"), "RequestTransferExit"))
    # --- tester present / control DTC / comm ---
    P.append(("3E_00", bytes.fromhex("3E00"), "TesterPresent zeroSubFunction"))
    P.append(("3E_80", bytes.fromhex("3E80"), "TesterPresent suppressPosRsp"))
    P.append(("85_01", bytes.fromhex("8501"), "ControlDTCSetting on"))
    P.append(("85_02", bytes.fromhex("8502"), "ControlDTCSetting off"))
    P.append(("86_01", bytes.fromhex("860100"), "ResponseOnEvent start"))
    P.append(("87", bytes.fromhex("87"), "LinkControl"))
    P.append(("83_00", bytes.fromhex("8300"), "AccessTimingParameter"))
    P.append(("2A_00", bytes.fromhex("2A00"), "ReadDataByPeriodicIdentifier"))
    P.append(("2C_01_F190", bytes.fromhex("2C01F190"), "DynamicallyDefineDID"))
    P.append(("2D_00", bytes.fromhex("2D00"), "WriteMemoryByAddress (deliberately incomplete)"))
    # --- read memory by address (several bases, 16-byte reads) ---
    for addr in (0x00000000, 0x00000010, 0x08000000, 0x08000010, 0x20000000, 0x40000000,
                 0x80000000, 0xC0000000, 0xFFFF0000):
        P.append(("23_%08X" % addr, bytes([0x23, 0x14]) + addr.to_bytes(4, "big") + b"\x00\x10",
                  "ReadMemoryByAddress addr=0x%08X len=16" % addr))
    return P


def main():
    done = set()
    if os.path.exists(OUT):
        for ln in open(OUT, encoding="utf-8"):
            try:
                done.add(json.loads(ln)["label"])
            except Exception:
                pass
    c = Cli()
    c.ensure_ra()
    f = open(OUT, "a", encoding="utf-8")
    hits = []
    t0 = time.time()
    for label, payload, desc in probes():
        if label in done:
            continue
        r = c.uds(payload)
        rec = {"label": label, "desc": desc, "req": binascii.hexlify(payload).decode().upper(),
               "kind": ("none" if r["uds"] is None else ("nrc" if r["uds"][0] == 0x7F else "pos")),
               "nrc": (r["uds"][2] if r["uds"] and r["uds"][0] == 0x7F and len(r["uds"]) > 2 else None),
               "uds": binascii.hexlify(r["uds"]).decode().upper() if r["uds"] else "",
               "ms": round(r["ms"], 1), "stale": r["stale"]}
        f.write(json.dumps(rec) + "\n")
        f.flush()
        interesting = not (rec["kind"] == "nrc" and rec["nrc"] == 0x11)
        if interesting:
            hits.append(rec)
            print("  *** %-28s %s" % (label, rec["uds"] or rec["kind"]), flush=True)
    f.close()
    c.close()
    print("=== %d probes, %d non-NRC11, %.0fs" % (len(done) + len(hits), len(hits), time.time() - t0))


if __name__ == "__main__":
    main()
