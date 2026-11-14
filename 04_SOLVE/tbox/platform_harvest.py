#!/usr/bin/env python3
"""CyberCar 平台附件收割（需要本队账号 cookie）。

用法（B 方案：拿到账号密码时）：
  python platform_harvest.py --login <username> <password>
用法（C 方案：已拿到 cybercar_session cookie 时）：
  python platform_harvest.py --cookie 'cybercar_session=...'
可选：--competition-id（默认取 ovpn 文件名里的 competition id）
产物：01_TARGETS/tbox/platform_harvest/<challenge_slug>/<filename>
索引：01_TARGETS/tbox/platform_harvest/INDEX.json（含 sha256 / size / downloadPath）
"""
import argparse, hashlib, json, os, ssl, sys, urllib.request, urllib.error

BASE = "https://175.27.210.153:9989"
COMP = "competition-ed3e7d452581978ccae13421"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "01_TARGETS", "tbox", "platform_harvest")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

def req(path, cookie=None, method="GET", body=None, raw=False):
    url = BASE + path
    data = None
    headers = {"Accept": "application/json", "Origin": BASE, "Referer": BASE + "/"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r, context=CTX, timeout=30) as resp:
        b = resp.read()
        if raw:
            return resp, b
        return resp.status, b

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--login", nargs=2, metavar=("USER", "PASS"))
    ap.add_argument("--cookie")
    ap.add_argument("--competition-id", default=COMP)
    ap.add_argument("--team-id")
    a = ap.parse_args()

    cookie = a.cookie
    if a.login:
        st, b = req("/api/v1/auth/login", method="POST", body={"username": a.login[0], "password": a.login[1]})
        print("login", st, b[:200])
        cookie = None  # need Set-Cookie; redo with cookie jar below
        # simple cookie jar
        import http.cookiejar
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPCookieProcessor(cj))
        r = urllib.request.Request(BASE + "/api/v1/auth/login", data=json.dumps({"username": a.login[0], "password": a.login[1]}).encode(),
                                   headers={"Content-Type": "application/json", "Origin": BASE, "Referer": BASE + "/"}, method="POST")
        with op.open(r, timeout=30) as resp:
            print("login2", resp.status)
        cookie = "; ".join(f"{c.name}={c.value}" for c in cj)
        print("cookie names:", [c.name for c in cj])

    if not cookie:
        print("no cookie; abort"); return 2

    st, b = req("/api/v1/bootstrap?competitionId=" + urllib.parse.quote(a.competition_id), cookie=cookie)
    boot = json.loads(b)
    os.makedirs(OUT, exist_ok=True)
    json.dump(boot, open(os.path.join(OUT, "bootstrap.json"), "w"), ensure_ascii=False, indent=1)
    print("bootstrap keys:", list(boot.keys()))

    challenges = []
    def walk(o):
        if isinstance(o, dict):
            if "attachments" in o or "hasAttachments" in o or "has_attachments" in o:
                if o.get("id") or o.get("slug") or o.get("title"):
                    challenges.append(o)
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
    walk(boot)
    seen=set(); uniq=[]
    for c in challenges:
        k=c.get("id") or c.get("slug") or c.get("title")
        if k in seen: continue
        seen.add(k); uniq.append(c)
    print(f"challenges with attachments: {len(uniq)}")
    index=[]
    for c in uniq:
        title = c.get("title") or c.get("slug") or c.get("id")
        print("==", title, "attachments:", len(c.get("attachments") or []))
        for at in (c.get("attachments") or []):
            dp = at.get("downloadPath") or at.get("download_path")
            fn = at.get("filename") or at.get("id") or "attachment.bin"
            print("   ", fn, at.get("sizeBytes"), dp)
            if not dp:
                index.append({"challenge": title, "filename": fn, "downloadPath": None, "error": "no downloadPath"})
                continue
            try:
                resp, data = req(dp, cookie=cookie, raw=True)
                d = os.path.join(OUT, str(c.get("slug") or title).replace("/", "_"))
                os.makedirs(d, exist_ok=True)
                p = os.path.join(d, fn)
                open(p, "wb").write(data)
                index.append({"challenge": title, "filename": fn, "path": p, "size": len(data),
                              "sha256": hashlib.sha256(data).hexdigest(), "downloadPath": dp})
                print("    saved", p, len(data))
            except Exception as e:
                index.append({"challenge": title, "filename": fn, "downloadPath": dp, "error": repr(e)})
                print("    ERR", e)
    json.dump(index, open(os.path.join(OUT, "INDEX.json"), "w"), ensure_ascii=False, indent=1)
    print("done ->", os.path.join(OUT, "INDEX.json"))

if __name__ == "__main__":
    main()
