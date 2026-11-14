#!/usr/bin/env python3
"""定量判定：vcu-reference.bin 的字节统计更像 ARM 代码还是更像随机。

方法：一阶 byte bigram 对数似然。
  训练集：T-BOX 固件真实 Thumb-2 代码区 fw[0x40:0x750]（04_SOLVE/fw 已确证是代码）。
  评分：mean log2 P(b_i | b_{i-1})，Laplace 平滑。
  对照：同一固件的代码区 / 数据区 / 200 份随机 1024B。
判据：若 vcu-reference 的分数落在随机对照分布内（且显著低于代码区），
      则 [否定] “该文件是 ARM 代码”。
"""
import math
import random
from collections import Counter, defaultdict

FW = "work/bundle2/tbox-firmware.dec.bin"
VCU = "work/bundle2/x/vcu-reference.bin"


def train(data):
    trans = defaultdict(Counter)
    for a, b in zip(data, data[1:]):
        trans[a][b] += 1
    # Laplace smoothing
    model = {}
    for a in range(256):
        tot = sum(trans[a].values()) + 256
        model[a] = {b: math.log2((trans[a][b] + 1) / tot) for b in range(256)}
    return model


def score(model, data):
    if len(data) < 2:
        return 0.0
    s = sum(model[a][b] for a, b in zip(data, data[1:]))
    return s / (len(data) - 1)


def main():
    fw = open(FW, "rb").read()
    vcu = open(VCU, "rb").read()
    code = fw[0x40:0x750]
    data_region = fw[0x780:0x9A0]  # SHA IV + S-box + AIV + K table（数据/常量区）
    model = train(code)

    print("# bigram model trained on fw code[0x40:0x750]")
    print(f"  score(fw code[0x40:0x750])      = {score(model, code):.4f} bits/byte")
    print(f"  score(fw data[0x780:0x9a0])     = {score(model, data_region):.4f} bits/byte")
    print(f"  score(vcu-reference whole)      = {score(model, vcu):.4f} bits/byte")
    print(f"  score(vcu-reference[0x28:])     = {score(model, vcu[0x28:]):.4f} bits/byte")
    print(f"  score(vcu-reference[0x340:])    = {score(model, vcu[0x340:]):.4f} bits/byte")

    random.seed(7)
    vals = []
    for _ in range(300):
        r = bytes(random.getrandbits(8) for _ in range(1024))
        vals.append(score(model, r))
    vals.sort()
    v = score(model, vcu)
    rank = sum(1 for x in vals if x <= v)
    print(f"\n  random controls n=300: min={vals[0]:.4f} p05={vals[15]:.4f} "
          f"median={vals[150]:.4f} p95={vals[285]:.4f} max={vals[-1]:.4f}")
    print(f"  vcu lands at percentile {rank/3:.1f}% of the random distribution")
    print(f"  gap to real code: {score(model, code) - v:.2f} bits/byte")


if __name__ == "__main__":
    main()
