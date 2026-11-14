#!/usr/bin/env python3
"""
Find where the cybercar .ovpn profile came from, using the local browser's own
download history (Chrome/Edge History SQLite: downloads + downloads_url_chains).

Scope discipline: only rows whose URL / referrer / target_path matches the
competition keywords are printed; everything else is skipped and never dumped.
The DB is copied to a temp file first because Chrome keeps it locked.
"""
import glob
import os
import shutil
import sqlite3
import sys
import tempfile

KEYS = ("cybercar", "ovpn", "competition", "range", "vpn", "ctf", "qwb",
        "10.230", "10.229", "10.224", "v2ray", "panel", "platform")

PROFILES = []
for root in (
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
    os.path.expandvars(r"%APPDATA%\Google\Chrome\User Data"),
):
    if os.path.isdir(root):
        for p in glob.glob(os.path.join(root, "*", "History")):
            PROFILES.append(p)
        p = os.path.join(root, "History")
        if os.path.isfile(p):
            PROFILES.append(p)

print(f"# found {len(PROFILES)} History DB(s)")
for p in PROFILES:
    print(f"#   {p}")

for src in PROFILES:
    print()
    print("=" * 78)
    print(f"DB: {src}")
    print("=" * 78)
    tmp = os.path.join(tempfile.gettempdir(),
                       f"hist_{abs(hash(src))}.sqlite")
    try:
        shutil.copy2(src, tmp)
    except Exception as e:
        print(f"  copy failed: {e}")
        continue
    try:
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        # --- downloads ---
        try:
            cur.execute("SELECT id, target_path, tab_url, tab_referrer_url, "
                        "site_url, referrer, mime_type, start_time "
                        "FROM downloads ORDER BY start_time DESC LIMIT 500")
            rows = cur.fetchall()
            print(f"  downloads rows: {len(rows)}")
            for r in rows:
                blob = " ".join(str(x) for x in r).lower()
                if any(k in blob for k in KEYS):
                    print(f"    [DL] id={r[0]} path={r[1]!r}")
                    print(f"         tab_url={r[2]!r} tab_referrer={r[3]!r}")
                    print(f"         site_url={r[4]!r} referrer={r[5]!r} mime={r[6]!r}")
        except Exception as e:
            print(f"  downloads query failed: {e}")
        # --- downloads_url_chains ---
        try:
            cur.execute("SELECT id, chain_index, url FROM downloads_url_chains "
                        "ORDER BY id DESC, chain_index LIMIT 2000")
            for r in cur.fetchall():
                if any(k in str(r[2]).lower() for k in KEYS):
                    print(f"    [DLC] id={r[0]} idx={r[1]} url={r[2]!r}")
        except Exception as e:
            print(f"  downloads_url_chains failed: {e}")
        # --- urls (visited) ---
        try:
            cur.execute("SELECT url, title, last_visit_time, visit_count "
                        "FROM urls ORDER BY last_visit_time DESC LIMIT 200000")
            seen = 0
            for r in cur.fetchall():
                if any(k in str(r[0]).lower() or k in str(r[1]).lower() for k in KEYS):
                    print(f"    [URL] {r[0]!r}  title={r[1]!r} visits={r[3]}")
                    seen += 1
                    if seen > 200:
                        print("    ... (truncated at 200)")
                        break
        except Exception as e:
            print(f"  urls query failed: {e}")
        con.close()
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
