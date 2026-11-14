#!/usr/bin/env python3
"""Does the CGW DoIP entity actually ROUTE, or does it terminate every request locally?

The single discriminating question: send the SAME UDS request (22 F190 = read VIN)
to many different target addresses -- including addresses that cannot possibly be
real ECUs (0xDEAD, 0xFFFE, 0x0000). Then compare:

  * which DoIP ACK/NACK codes come back (0x8002 / 0x8003),
  * which source address the 0x8001 response carries,
  * whether the UDS payload is identical.

A gateway that forwards would answer "unknown target address" / "target unreachable"
for 0xDEAD and something different for a known ECU. A local stub answers the same
thing for every target, from its own address, with identical payload.

Reuses ../../cgw/doip_client.py.
"""
import os, sys, json, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "cgw"))
from doip_client import (DoIPClient, PT_ROUTING_ACT_REQ, PT_ALIVE_CHECK_REQ,
                         PT_ENTITY_STATUS_REQ, PT_DIAG_POWER_MODE_REQ,
                         PT_VEHICLE_ID_REQ_VIN, hexs)  # noqa: E402

OUT = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "cgw-web",
                                   "0610_doip_ta_discriminator.jsonl"))

HOST = "10.229.221.2"
SA = 0x0E00

# Targets chosen so that the answer pattern is interpretable:
#   0x1000  the entity that has been answering all along
#   0x0E00  ourselves (a tester address, must be rejected as a target)
#   0x0E05  a plausible BCM-ish address on the *other* subnet
#   0xDEAD  cannot exist
#   0xFFFE  reserved / cannot exist
#   0x0000  invalid
TARGETS = [0x1000, 0x0E00, 0x1001, 0x0001, 0x0E05, 0x0E06, 0x0E07,
           0x07E0, 0xDEAD, 0xFFFE, 0x0000]

f = open(OUT, "w", encoding="utf-8")


def emit(obj):
    line = json.dumps(obj, ensure_ascii=False)
    f.write(line + "\n")
    f.flush()
    print(line, flush=True)


def main():
    with DoIPClient(host=HOST, verbose=False) as c:
        # ---- 1. routing activation baseline ------------------------------
        ra, frames = c.routing_activation(sa=SA, act_type=0x00, timeout=2.0)
        emit({"step": "ra_sa0e00_act00", "resp": ra,
              "raw": [x.as_dict() for x in frames]})

        # ---- 2. the TA discriminator -------------------------------------
        rows = []
        for ta in TARGETS:
            r = c.diag(SA, ta, bytes.fromhex("22f190"), timeout=1.6)
            row = {"step": "diag_22F190", "ta": "0x%04X" % ta,
                   "acks": r["acks"], "nacks": r["nacks"],
                   "uds": r["uds"], "latency_ms": r["latency_ms"],
                   "n_frames": len(r["frames"]), "frames": r["frames"]}
            rows.append(row)
            emit(row)
            time.sleep(0.12)

        # ---- 3. verdict table --------------------------------------------
        print("\n=== 22 F190 vs target address ===")
        print("%-8s %-14s %-14s %-42s" % ("TA", "DIP-ACK", "DIP-NACK", "UDS answer"))
        for r in rows:
            ack = ",".join(a["code"] or "-" for a in r["acks"]) or "-"
            nack = ",".join(a["code"] or "-" for a in r["nacks"]) or "-"
            uds = "; ".join("%s->%s %s" % (u["from"], u["to"], u["hex"])
                            for u in r["uds"]) or "<none>"
            print("%-8s %-14s %-14s %-42s" % (r["ta"], ack, nack, uds[:42]))
            emit({"step": "verdict_row", "ta": r["ta"], "ack": ack,
                  "nack": nack, "uds": uds})

        # ---- 4. routing activation matrix (other SAs / activation types) --
        print("\n=== routing activation matrix ===")
        for sa in (0x0E00, 0x0E80, 0x1000, 0x0F00, 0x0700, 0x0001):
            for act in (0x00, 0x01, 0xE0):
                try:
                    resp, fr = c.routing_activation(sa=sa, act_type=act, timeout=1.2)
                except Exception as e:
                    resp, fr = {"error": repr(e)}, []
                emit({"step": "ra", "sa": "0x%04X" % sa, "act_type": "0x%02X" % act,
                      "resp": resp})
                print("  SA=%04X act=%02X -> %s" % (sa, act, resp), flush=True)
                time.sleep(0.1)

        # ---- 5. alive check / entity status / power mode ------------------
        print("\n=== misc DoIP requests ===")
        for name, pt, payload in (
            ("alive_check_0x0007", PT_ALIVE_CHECK_REQ, b""),
            ("entity_status_0x4001", PT_ENTITY_STATUS_REQ, b""),
            ("power_mode_0x4004", PT_DIAG_POWER_MODE_REQ, b""),
            ("ident_vin_0x0003", PT_VEHICLE_ID_REQ_VIN, b"CV6FF52FEE9EDDD86"),
        ):
            fr = c.transact(pt, payload, duration=1.5)
            emit({"step": name, "frames": [x.as_dict() for x in fr]})
            print("  %-22s -> %s" % (name, [x.as_dict() for x in fr]), flush=True)
            time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    finally:
        f.close()
        print("\nevidence:", OUT)
