#!/usr/bin/env python3
"""
CyberCar platform harvester (T01 side quest: find the OTA ZIP / engineering package).

The platform at https://175.27.210.153:9989 is a SPA; every useful byte sits behind
`cybercar_session`. Challenge objects carry
    attachments[] = {id, filename, sizeBytes, downloadPath}
and the platform *scores* whether you actually downloaded them
(`attachment_without_download` = disqualification), so the correct move is to
download attachments as the team account.

Auth sources, in order of preference:
  1. --cookie 'cybercar_session=...'   (paste from DevTools -> Application -> Cookies)
  2. --user U --password P             (normal POST /api/v1/auth/login; the API only
                                        requires a same-origin Origin/Referer, which we set)

Nothing is written to the platform. All output lands in 01_TARGETS/tsp/platform/.

Usage:
  python fetch_platform.py --cookie 'cybercar_session=abc'
  python fetch_platform.py --user myuser --password 'mypass'
  python fetch_platform.py --user u --password p --dry-run     # list only, no downloads
"""
import argparse
import hashlib
import json
import os
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://175.27.210.153:9989"
COMPETITION_ID = "competition-ed3e7d452581978ccae13421"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "01_TARGETS", "tsp", "platform")
ATT = os.path.join(OUT, "attachments")
EVID = os.path.join(ROOT, "03_EVIDENCE", "tsp")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def mk_session(cookie=None, user=None, password=None):
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Origin": BASE,
        "Referer": BASE + "/",
    })
    if cookie:
        # accept both 'a=b; c=d' and a bare value
        if "=" not in cookie:
            cookie = "cybercar_session=" + cookie
        s.headers["Cookie"] = cookie
        return s, "cookie"
    if user:
        r = s.post(BASE + "/api/v1/auth/login",
                   json={"username": user, "password": password}, timeout=30)
        print(f"[login] {r.status_code} {r.text[:300]}")
        if r.status_code != 200:
            sys.exit(f"login failed: {r.status_code}")
        return s, "login"
    sys.exit("need --cookie or --user/--password")


def jget(s, path, **kw):
    r = s.get(BASE + path, timeout=60, **kw)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"_raw": r.text[:400]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookie")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--competition", default=COMPETITION_ID)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    os.makedirs(ATT, exist_ok=True)
    os.makedirs(EVID, exist_ok=True)
    log = open(os.path.join(EVID, "0140_platform_harvest_log.txt"), "a",
               encoding="utf-8")
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")

    def P(*args):
        line = " ".join(str(x) for x in args)
        print(line)
        log.write(line + "\n")
        log.flush()

    P("=" * 78)
    P(f"[{stamp}] harvest start  competition={a.competition}")
    s, how = mk_session(a.cookie, a.user, a.password)
    P(f"auth mode: {how}")

    code, chk = jget(s, "/api/v1/auth/check")
    P(f"[auth/check] {code} {json.dumps(chk, ensure_ascii=False)}")
    if not chk.get("authenticated"):
        P("!! not authenticated - aborting")
        sys.exit(2)

    code, boot = jget(s, f"/api/v1/bootstrap?competitionId={a.competition}")
    P(f"[bootstrap] http={code} bytes={len(json.dumps(boot))}")
    with open(os.path.join(OUT, f"bootstrap_{int(time.time())}.json"), "w",
              encoding="utf-8") as f:
        json.dump(boot, f, ensure_ascii=False, indent=1)

    if code != 200:
        P("bootstrap failed: " + json.dumps(boot, ensure_ascii=False)[:600])
        sys.exit(3)

    comp = boot.get("competition") or boot.get("data", {}).get("competition") or {}
    P(f"competition: {comp.get('name') or comp.get('title') or comp.get('id')} "
      f"mode={comp.get('mode')}")

    # challenges may live at several levels depending on API version
    challenges = (boot.get("challenges")
                  or boot.get("data", {}).get("challenges")
                  or [])
    if isinstance(challenges, dict):
        challenges = challenges.get("items") or []
    P(f"challenges: {len(challenges)}")

    # ---------------------------------------------------------------
    # also emit a team-readable digest, so the whole team can read the
    # challenge texts without needing the platform
    # ---------------------------------------------------------------
    md = ["# CyberCar 平台题目摘要（自动生成）", "",
          f"- 生成时间：{stamp}",
          f"- competition：`{comp.get('id') or a.competition}` "
          f"{comp.get('name') or comp.get('title') or ''}",
          f"- 题目数：{len(challenges)}", ""]
    manifest = []
    for ch in challenges:
        ch = ch or {}
        cid = ch.get("id")
        slug = ch.get("slug")
        title = ch.get("title")
        atts = ch.get("attachments") or []
        P("-" * 70)
        P(f"  [{slug}] {title}   id={cid}")
        P(f"    runtimeKind={ch.get('runtimeKind') or ch.get('runtime_kind')} "
          f"flagMode={ch.get('flagMode') or ch.get('flag_mode')} "
          f"score={ch.get('baseScore') or ch.get('base_score')}")
        desc = (ch.get("description") or "").strip()
        if desc:
            P("    description: " + desc.replace("\n", "\n                 ")[:1500])
        P(f"    attachments: {len(atts)}")
        md += [f"## {slug} — {title}", "",
               f"- id: `{cid}`",
               f"- runtimeKind: `{ch.get('runtimeKind') or ch.get('runtime_kind')}`",
               f"- flagMode: `{ch.get('flagMode') or ch.get('flag_mode')}`"
               f"  （dynamic = 每队每实例唯一，必须从靶场/附件里取）",
               f"- baseScore: {ch.get('baseScore') or ch.get('base_score')}",
               f"- boundVehicleInstanceIds: "
               f"{ch.get('boundVehicleInstanceIds') or ch.get('bound_vehicle_instance_ids')}",
               ""]
        # ---- the authoritative target address lives on the RUN, not in any doc ----
        run = ch.get("run") or ch.get("currentRun") or ch.get("current_run") or {}
        if run:
            host = run.get("accessHost") or run.get("access_host")
            port = run.get("accessPort") or run.get("access_port")
            md += ["**运行实例接入点（权威目标地址）**：", "",
                   f"- status: `{run.get('status')}`",
                   f"- accessHost:accessPort = `{host}:{port}`",
                   f"- entryPort: `{ch.get('entryPort') or ch.get('entry_port')}`",
                   f"- vehicleInstanceId: `{run.get('vehicleInstanceId') or run.get('vehicle_instance_id')}`",
                   ""]
            ports = run.get("accessPorts") or run.get("access_ports") or []
            if ports:
                md.append("- accessPorts:")
                for p in ports:
                    md.append(f"  - {p.get('protocol')} "
                              f"host {p.get('hostPort') or p.get('host_port')} -> "
                              f"guest {p.get('guestPort') or p.get('guest_port')}")
                md.append("")
            P(f"    RUN accessHost={host}:{port} status={run.get('status')}")
        else:
            P("    RUN: <none> (attachment-only or not started)")
        if desc:
            md += ["```text", desc, "```", ""]
        if atts:
            md += ["附件："]
            for at in atts:
                md.append(f"- `{at.get('filename')}` "
                          f"({at.get('sizeBytes') or at.get('size_bytes') or 0} B) "
                          f"`{at.get('downloadPath') or at.get('download_path')}`")
            md.append("")
        for at in atts:
            aid = at.get("id")
            fn = at.get("filename") or aid or "attachment"
            size = at.get("sizeBytes") or at.get("size_bytes") or 0
            dp = at.get("downloadPath") or at.get("download_path") or ""
            P(f"      - {fn} ({size} B) downloadPath={dp!r}")
            rec = {"challenge_id": cid, "challenge_slug": slug,
                   "challenge_title": title, "attachment_id": aid,
                   "filename": fn, "declared_size": size, "download_path": dp}
            if a.dry_run or not dp:
                manifest.append(rec)
                continue
            url = dp if dp.startswith("http") else BASE + dp
            try:
                with s.get(url, stream=True, timeout=300, allow_redirects=True) as r:
                    P(f"        GET {url} -> {r.status_code} "
                      f"ct={r.headers.get('Content-Type')} "
                      f"cl={r.headers.get('Content-Length')}")
                    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in fn)
                    dest = os.path.join(ATT, f"{slug or cid}__{safe}")
                    h = hashlib.sha256()
                    n = 0
                    with open(dest, "wb") as fo:
                        for chunk in r.iter_content(1 << 16):
                            fo.write(chunk)
                            h.update(chunk)
                            n += len(chunk)
                    rec.update({"saved_to": dest, "bytes": n,
                                "sha256": h.hexdigest(), "http": r.status_code})
                    P(f"        saved {dest}  {n} B  sha256={h.hexdigest()}")
            except Exception as e:
                rec["error"] = f"{type(e).__name__}: {e}"
                P(f"        !! download error {rec['error']}")
            manifest.append(rec)

    mp = os.path.join(OUT, "attachments_manifest.json")
    with open(mp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    mdp = os.path.join(OUT, "challenges.md")
    with open(mdp, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    P(f"challenges digest -> {mdp}")
    P("=" * 78)
    P(f"manifest -> {mp}")
    P(f"attachments downloaded: {sum(1 for m in manifest if m.get('sha256'))}"
      f" / {len(manifest)}")
    for m in manifest:
        if m.get("sha256"):
            P(f"  {m['sha256']}  {m['bytes']:>10}  {m['saved_to']}")
    log.close()


if __name__ == "__main__":
    main()
