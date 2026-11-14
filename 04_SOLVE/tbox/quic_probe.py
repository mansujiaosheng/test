import asyncio, ssl, sys
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.events import HandshakeCompleted

HOST='10.230.164.3'; PORT=8443

async def main():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
    cfg.verify_mode = ssl.CERT_NONE
    try:
        async with connect(HOST, PORT, configuration=cfg, wait_connected=True) as client:
            print('QUIC CONNECTED', client._quic.host_cid.hex())
            http = H3Connection(client._quic)
            sid = client._quic.get_next_available_stream_id()
            http.send_headers(sid, [(b':method',b'GET'),(b':scheme',b'https'),(b':authority',b'tbox'),(b':path',b'/')], end_stream=True)
            client.transmit()
            done = asyncio.Event()
            def on_ev(ev):
                print('EVENT', type(ev).__name__, getattr(ev,'headers',None), getattr(ev,'data',None)[:80] if getattr(ev,'data',None) else '')
                if isinstance(ev, DataReceived) and ev.stream_ended: done.set()
            client._quic_event_handler = on_ev
            try:
                await asyncio.wait_for(done.wait(), timeout=6)
            except asyncio.TimeoutError:
                print('no h3 response within 6s')
    except Exception as e:
        print('QUIC FAIL:', type(e).__name__, e)

asyncio.run(main())
