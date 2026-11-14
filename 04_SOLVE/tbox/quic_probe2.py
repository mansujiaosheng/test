import asyncio, ssl, sys
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

HOST='10.230.164.3'; PORT=8443

async def main():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.idle_timeout = 5.0
    try:
        async with connect(HOST, PORT, configuration=cfg, wait_connected=True) as client:
            print('QUIC CONNECTED')
            client.transmit()
            await asyncio.sleep(1)
    except asyncio.TimeoutError:
        print('QUIC TIMEOUT (no server response)')
    except Exception as e:
        print('QUIC FAIL:', type(e).__name__, repr(e))

asyncio.run(asyncio.wait_for(main(), timeout=15))
