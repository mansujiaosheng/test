import socket, struct, binascii
def pkt(ptype, payload=b"", ver=0x02):
    return bytes([ver, 0xFF-ver]) + struct.pack(">H", ptype) + struct.pack(">I", len(payload)) + payload
for target in [("10.230.164.4",13400),("<broadcast>",13400)]:
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(3)
    try:
        s.sendto(pkt(0x0001), target)
        print("sent to", target)
        for _ in range(6):
            try:
                data, addr = s.recvfrom(2048)
                print(" FROM", addr, binascii.hexlify(data).decode())
                if len(data) >= 8:
                    vin=data[8:25]
                    print("   VIN?", vin)
            except socket.timeout:
                break
    except Exception as e:
        print("ERR", target, e)
    s.close()
