#!/usr/bin/env python3
"""Raw h2c / gRPC probe. Detects whether a Go server speaks HTTP/2 cleartext.
Read-only: sends HTTP/2 preface+SETTINGS and (if h2c) one gRPC health-check HEADERS."""
import socket, sys, time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ftype, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + \
        (stream & 0x7FFFFFFF).to_bytes(4, "big") + payload


def probe(host, port, timeout=6):
    out = {"target": f"{host}:{port}"}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        out["error"] = f"connect: {e}"
        return out
    s.settimeout(timeout)
    # SETTINGS: MAX_CONCURRENT_STREAMS=100
    settings = frame(0x4, 0x0, 0, b"\x00\x03\x00\x00\x00\x64")
    try:
        s.sendall(PREFACE + settings)
        time.sleep(0.4)
        data = s.recv(4096)
    except Exception as e:
        out["error"] = f"recv: {e}"
        s.close()
        return out
    out["response_first_200_hex"] = data[:200].hex()
    out["response_first_200_repr"] = repr(data[:200])
    if len(data) >= 9:
        ln = int.from_bytes(data[0:3], "big")
        ftype, flags = data[3], data[4]
        sid = int.from_bytes(data[5:9], "big") & 0x7FFFFFFF
        out["frame"] = {"len": ln, "type": ftype, "flags": flags, "stream": sid}
        out["is_h2c"] = ftype == 4  # SETTINGS
    else:
        out["is_h2c"] = False
    # If h2c, try a gRPC health check as HTTP/2 HEADERS using h2 lib
    if out.get("is_h2c"):
        try:
            import h2.connection, h2.config
            c = h2.connection.H2Connection(config=h2.config.H2Configuration(
                client_side=True, header_encoding="utf-8"))
            c.initiate_connection()
            c.update_settings({})
            sid = c.get_next_available_stream_id()
            c.send_headers(sid, [
                (":method", "POST"), (":scheme", "http"),
                (":authority", f"{host}:{port}"),
                (":path", "/grpc.health.v1.Health/Check"),
                ("content-type", "application/grpc"), ("te", "trailers"),
                ("grpc-timeout", "3S"),
            ], end_stream=False)
            c.send_data(sid, b"\x00\x00\x00\x00\x00", end_stream=True)
            s.sendall(c.data_to_send())
            time.sleep(0.6)
            raw = s.recv(8192)
            evs = c.receive_data(raw)
            out["grpc_events"] = [str(e) for e in evs][:20]
            hdrs, body = [], b""
            for e in evs:
                if hasattr(e, "headers"):
                    hdrs.append(e.headers)
                if hasattr(e, "data"):
                    body += e.data
            out["grpc_headers"] = hdrs
            out["grpc_body_hex"] = body[:120].hex()
            out["grpc_body_repr"] = repr(body[:120])
        except Exception as e:
            out["grpc_error"] = f"{type(e).__name__}: {e}"
    s.close()
    return out


if __name__ == "__main__":
    import json
    res = []
    for hp in sys.argv[1:]:
        h, p = hp.rsplit(":", 1)
        r = probe(h, int(p))
        res.append(r)
        print(json.dumps(r, indent=1, ensure_ascii=False))
        print("=" * 70)
