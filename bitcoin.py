import selectors
import socket
import config
from structs import *
from messages import *
import lib

class node:
    def __init__(self, sock):
        self.sock = sock

class bitcoin:
    def __init__(self):
        self.nodes = {}

        self.sel = selectors.DefaultSelector()
        self.listensock = self.sock_listen(config.listen_port)
        self.sock_connect(config.seed_addr)

        self.slicedmsg = b""

    def sock_accept(self, sock):
        conn, addr = sock.accept()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.sock_read)
        fd = conn.fileno()
        self.nodes[fd] = node(conn)
        lib.info("new connection: {}({})", addr, fd)

    def sock_read(self, sock):
        data = sock.recv(4096)
        fd = sock.fileno()
        if data:
            self.on_recv(fd, data)
        else:
            lib.info("disconnect: {}", fd)
            self.sel.unregister(sock)
            sock.close()

    def sock_connect(self, addr):
        sock = socket.create_connection(addr)
        self.sel.register(sock, selectors.EVENT_READ, self.sock_read)
        fd = sock.fileno()
        self.nodes[fd] = node(sock)
        lib.info("connect to: {}({})", addr, fd)
        msg = s_message("version", m_version(0).tobytes())
        self.send(fd, msg)

    def sock_listen(self, port):
        sock = socket.socket()
        sock.bind(("localhost", port))
        sock.listen()
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, self.sock_accept)
        return sock

    def run(self):
        while True:
            events = self.sel.select()
            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

    def on_recv(self, fd, data):
        if self.slicedmsg and len(self.slicedmsg) > 0:
            data = self.slicedmsg + data
        while True:
            if not data or len(data) <= 0:
                break
            (msg, data, self.slicedmsg) = s_message.load(data)
            if not msg:
                break
            self.handle(fd, msg)

    def send(self, fd, msg):
        node = self.nodes[fd]
        data = msg.tobytes()
        sent = node.sock.send(data)
        lib.info("-> {}:{}/{}", msg.command, sent, len(data))

    def handle(self, fd, msg):
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
                return handler(fd, payload)
        lib.err("unknown command: <{}>", msg.command)

    def handle_version(self, fd, payload):
        msg = s_message("verack", m_verack().tobytes())
        self.send(fd, msg)

    def handle_verack(self, fd, payload):
        #msg = s_message("getaddr", m_getaddr().tobytes())
        #self.send(fd, msg)
        pass

    def handle_addr(self, fd, payload):
        # do nothing
        pass

    def handle_inv(self, fd, payload):
        pass

    def handle_getdata(self, fd, payload):
        pass

    def handle_notfound(self, fd, payload):
        pass

    def handle_getblocks(self, fd, payload):
        pass

    def handle_getheaders(self, fd, payload):
        # do nothing
        pass

    def handle_tx(self, fd, payload):
        pass

    def handle_block(self, fd, payload):
        pass

    def handle_headers(self, fd, payload):
        pass

    def handle_getaddr(self, fd, payload):
        pass
 
    def handle_mempool(self, fd, payload):
        pass

    def handle_checkorder(self, fd, payload):
        pass

    def handle_submitorder(self, fd, payload):
        pass

    def handle_reply(self, fd, payload):
        pass

    def handle_ping(self, fd, payload):
        msg = s_message("pong", m_pong(payload.nonce).tobytes())
        self.send(fd, msg)

    def handle_pong(self, fd, payload):
        pass

    def handle_reject(self, fd, payload):
        pass

    def handle_filterload(self, fd, payload):
        pass

    def handle_fileteradd(self, fd, payload):
        pass

    def handle_filterclear(self, fd, payload):
        pass

    def handle_merkleblock(self, fd, payload):
        pass

    def handle_alert(self, fd, payload):
        pass

    def handle_sendheaders(self, fd, payload):
        pass

    def handle_feefilter(self, fd, payload):
        pass

    def handle_sendcmpct(self, fd, payload):
        pass

    def handle_cmpctblock(self, fd, payload):
        pass

    def handle_getblocktxn(self, fd, payload):
        pass

    def handle_blocktxn(self, fd, payload):
        pass
