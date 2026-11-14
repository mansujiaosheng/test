#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p1_shape.py - establish the response *shape* for unknown TA / functional addressing,
so that TA enumeration has a real discriminator.

Questions:
  Q1 unknown TA + 22F190 -> 7F2231 from 0x1000?  or silence?
  Q2 CAN-style IDs (0x7E0/0x7E8/0x7E1/0x7E9) as TA -> anything?
  Q3 functional addressing TA=0xE400 / 0xE000 -> anything?
  Q4 SA variations (0x0E00/0x0E80/0x07E0/0xF187) -> does SA change the answer?
  Q5 does a *known* DID at a *known-good* TA differ from unknown TA in latency?
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dx
from dx import hx, verdict

TEST = [
    # (label, ta, uds)
    ("ta_unk_0123_22F190", 0x0123, "22F190"),
    ("ta_unk_FFFF_22F190", 0xFFFF, "22F190"),
    ("ta_can_07E0_22F190", 0x07E0, "22F190"),
    ("ta_can_07E8_22F190", 0x07E8, "22F190"),
    ("ta_can_07E1_22F190", 0x07E1, "22F190"),
    ("ta_can_07E9_22F190", 0x07E9, "22F190"),
    ("ta_can_07E0_3E00",   0x07E0, "3E00"),
    ("ta_fn_E400_22F190",  0xE400, "22F190"),
    ("ta_fn_E000_22F190",  0xE000, "22F190"),
    ("ta_fn_E400_3E00",    0xE400, "3E00"),
    ("ta_gw_1000_22F190_sa07E0", 0x1000, "22F190"),   # sa overridden below
    ("ta_gw_1000_22F1A1",  0x1000, "22F1A1"),
    ("ta_gw_1000_22F1A2",  0x1000, "22F1A2"),
    ("ta_gw_1000_22F1B0",  0x1000, "22F1B0"),
    ("ta_gw_1000_22F186",  0x1000, "22F186"),
    ("ta_gw_1000_22F18C",  0x1000, "22F18C"),
    ("ta_gw_1000_22F191",  0x1000, "22F191"),
    ("ta_gw_1000_22F194",  0x1000, "22F194"),
    ("ta_gw_1000_22F19E",  0x1000, "22F19E"),
    ("ta_gw_1000_22F1AF",  0x1000, "22F1AF"),
]


def main():
    d = dx.link()
    print("# ident:", [(pt, hx(pl)) for _, pt, pl in d.ident()])
    print("%-28s %-6s %-34s %-8s %s" % ("label", "TA", "verdict", "ms", "src->dst"))
    for label, ta, u in TEST:
        sa = None
        if label.endswith("_sa07E0"):
            sa = 0x07E0
        try:
            r = d.uds(bytes.fromhex(u), ta=ta, sa=sa)
        except PermissionError as e:
            print(label, "GUARDED", e)
            continue
        src = r["frames"][0]["sa"] if r["frames"] else None
        dst = r["frames"][0]["ta"] if r["frames"] else None
        print("%-28s %-6s %-34s %-8.1f %s" % (label, "0x%04X" % ta, verdict(r), r["ms"],
              ("0x%04X->0x%04X" % (src, dst)) if src is not None else "-"))
        dx.save("p1_" + label, "shape probe: TA/SA discriminator", d, r,
                {"ta": "0x%04X" % ta, "question": "response shape for unknown TA / functional addressing"})
        d.ra()  # re-activate for next (some stacks drop the connection state)
    d.close()


if __name__ == "__main__":
    main()
