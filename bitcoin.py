import selectors
import socket
import config
from structs import *
from messages import *
import lib

class bitcoin():
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.sock_listen(8333)
        self.sock_connect(config.seed_addr)

        self.slicedmsg = b""

    def sock_accept(self, sock, mask):
        conn, addr = sock.accept()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.sock_read)
        lib.info("new connection: {}({})", addr, conn)

    def sock_read(self, conn, mask):
        data = conn.recv(4096)
        if data:
            self.on_recv(data)
        else:
            lib.info("disconnect: {}", conn)
            self.sel.unregister(conn)
            conn.close()

    def sock_connect(self, addr):
        self.sock = socket.create_connection(addr)
        self.sel.register(self.sock, selectors.EVENT_READ, self.sock_read)
        lib.info("connect to: {}", addr)

    def sock_listen(self, port):
        self.listensock = socket.socket()
        self.listensock.bind(("localhost", port))
        self.listensock.listen()
        self.listensock.setblocking(False)
        self.sel.register(self.listensock, selectors.EVENT_READ, self.sock_accept)

    def run(self):
        msg = s_message("version", m_version(0).tobytes())
        self.send(msg)

        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def on_recv(self, data):
        if self.slicedmsg and len(self.slicedmsg) > 0:
            data = self.slicedmsg + data
        while True:
            if not data or len(data) <= 0:
                break
            (msg, data, self.slicedmsg) = s_message.load(data)
            if not msg:
                break
            self.handle(msg)

    def send(self, msg):
        data = msg.tobytes()
        sent = self.sock.send(data)
        lib.info("-> {}:{}/{}", msg.command, sent, len(data))

    def handle(self, msg):
        msgtypes = ["version", "verack", "addr", "inv", "getdata", "notfound", "getblocks",
            "getheaders", "tx", "block", "headers", "getaddr", "mempool", "checkorder",
            "submitorder", "reply", "ping", "pong", "reject", "filterload", "fileteradd",
            "filterclear", "merkleblock", "alert", "sendheaders", "feefilter", "sendcmpct",
            "cmpctblock", "getblocktxn", "blocktxn"]

        found = False
        for t in msgtypes:
            if msg.command[:len(t)] == t:
                found = True
                handler = getattr(self, "handle_" + t, None)
                if not handler:
                    lib.err("no handler for <{}>", t)
                    return
                lib.info("<- <{}>", t)

                clsname = "m_" + t
                if clsname not in globals():
                    lib.err("no class for <{}>", t)
                    return

                payload = globals()[clsname].load(msg.payload)
                if config.debug_enabled:
                    payload.debug()
                return handler(payload)
        lib.err("unknown command: <{}>", msg.command)

    def handle_version(self, payload):
        msg = s_message("verack", m_verack().tobytes())
        self.send(msg)

    def handle_verack(self, payload):
        #msg = s_message("getaddr", m_getaddr().tobytes())
        #self.send(msg)
        pass

    def handle_addr(self, payload):
        # do nothing
        pass

    def handle_inv(self, payload):
        pass

    def handle_getdata(self, payload):
        pass

    def handle_notfound(self, payload):
        pass

    def handle_getblocks(self, payload):
        pass

    def handle_getheaders(self, payload):
        # do nothing
        pass

    def handle_tx(self, payload):
        pass

    def handle_block(self, payload):
        pass

    def handle_headers(self, payload):
        pass

    def handle_getaddr(self, payload):
        pass
 
    def handle_mempool(self, payload):
        pass

    def handle_checkorder(self, payload):
        pass

    def handle_submitorder(self, payload):
        pass

    def handle_reply(self, payload):
        pass

    def handle_ping(self, payload):
        msg = s_message("pong", m_pong(payload.nonce).tobytes())
        self.send(msg)

    def handle_pong(self, payload):
        pass

    def handle_reject(self, payload):
        pass

    def handle_filterload(self, payload):
        pass

    def handle_fileteradd(self, payload):
        pass

    def handle_filterclear(self, payload):
        pass

    def handle_merkleblock(self, payload):
        pass

    def handle_alert(self, payload):
        pass

    def handle_sendheaders(self, payload):
        pass

    def handle_feefilter(self, payload):
        pass

    def handle_sendcmpct(self, payload):
        pass

    def handle_cmpctblock(self, payload):
        pass

    def handle_getblocktxn(self, payload):
        pass

    def handle_blocktxn(self, payload):
        pass
