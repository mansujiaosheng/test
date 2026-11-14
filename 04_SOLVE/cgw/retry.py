import socket, time
def connect_retry(host, port, timeout=3.0, tries=4, gap=0.4, bind=None):
    last=None
    for i in range(tries):
        s=socket.socket(); s.settimeout(timeout)
        try:
            if bind: s.bind(bind)
            s.connect((host,port)); return s
        except Exception as e:
            last=e; s.close(); time.sleep(gap)
    raise last
