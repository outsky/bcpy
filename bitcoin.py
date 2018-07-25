import selectors
import socket
import config
from structs import *
from messages import *
import lib

class Node:
    def __init__(self, sock):
        self.sock = sock

class BitCoin:
    def __init__(self):
        self.nodes = {}
        self.slicedmsg = b""

        self.sel = selectors.DefaultSelector()
        self.listensock = self.sock_listen(config.listen_port)
        self.sock_connect(config.seed_addr)


    def sock_accept(self, sock):
        conn, addr = sock.accept()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.sock_read)
        fd = conn.fileno()
        self.nodes[fd] = Node(conn)
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
        self.nodes[fd] = Node(sock)
        lib.info("connect to: {}({})", addr, fd)
        msg = Message("version", Version(0).tobytes())
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
            for key, _ in self.sel.select():
                key.data(key.fileobj)

    def on_recv(self, fd, data):
        if self.slicedmsg and len(self.slicedmsg) > 0:
            data = self.slicedmsg + data
        while True:
            if not data or len(data) <= 0:
                break
            (msg, data, self.slicedmsg) = Message.load(data)
            if not msg:
                break
            self.handle(fd, msg)

    def send(self, fd, msg):
        node = self.nodes[fd]
        data = msg.tobytes()
        sent = node.sock.send(data)
        lib.info("-> {}:{}/{}", msg.command, sent, len(data))

    def handle(self, fd, msg):
        msgtypes = {"version": "Version", "verack": "VerAck", "addr": "Addr", "inv": "Inv", 
            "getdata": "GetData", "notfound": "NotFound", "getblocks": "GetBlocks",
            "getheaders": "GetHeaders", "tx": "Tx", "block": "Block", "headers": "Headers",
            "getaddr": "GetAddr", "mempool": "MemPool", "checkorder": "CheckOrder",
            "submitorder": "SubmitOrder", "reply": "Reply", "ping": "Ping", "pong": "Pong",
            "reject": "Reject", "filterload": "FilterLoad", "fileteradd": "FilterAdd",
            "filterclear": "FilterClear", "merkleblock": "MerkleBlock", "alert": "Alert",
            "sendheaders": "SendHeaders", "feefilter": "FeeFilter", "sendcmpct": "SendCmpct",
            "cmpctblock": "CmpctBlock", "getblocktxn": "GetBlockTxn", "blocktxn": "BlockTxn"}

        cmd = msg.command
        if cmd not in msgtypes:
            lib.err("unknown command: <{}>({})", cmd, cmd.encode("utf-8"))
            return

        clsname = msgtypes[cmd]
        handler = getattr(self, "handle_" + clsname, None)
        if not handler:
            lib.err("no handler for <{}, {}>", cmd, clsname)
            return
        lib.info("<- <{}>", cmd)

        if clsname not in globals():
            lib.err("no class for <{}, {}>", cmd, clsname)
            return

        payload = globals()[clsname].load(msg.payload)
        if config.debug_enabled:
            payload.debug()
        return handler(fd, payload)

    def handle_Version(self, fd, payload):
        msg = Message("verack", VerAck().tobytes())
        self.send(fd, msg)

    def handle_VerAck(self, fd, payload):
        #msg = Message("getaddr", GetAddr().tobytes())
        #self.send(fd, msg)
        pass

    def handle_Addr(self, fd, payload):
        # do nothing
        pass

    def handle_Inv(self, fd, payload):
        pass

    def handle_GetData(self, fd, payload):
        pass

    def handle_NotFound(self, fd, payload):
        pass

    def handle_GetBlocks(self, fd, payload):
        pass

    def handle_GetHeaders(self, fd, payload):
        # do nothing
        pass

    def handle_Tx(self, fd, payload):
        pass

    def handle_Block(self, fd, payload):
        pass

    def handle_Headers(self, fd, payload):
        pass

    def handle_GetAddr(self, fd, payload):
        pass
 
    def handle_MemPool(self, fd, payload):
        pass

    def handle_CheckOrder(self, fd, payload):
        pass

    def handle_SubmitOrder(self, fd, payload):
        pass

    def handle_Reply(self, fd, payload):
        pass

    def handle_Ping(self, fd, payload):
        msg = Message("pong", Pong(payload.nonce).tobytes())
        self.send(fd, msg)

    def handle_Pong(self, fd, payload):
        pass

    def handle_Reject(self, fd, payload):
        pass

    def handle_FilterLoad(self, fd, payload):
        pass

    def handle_FileterAdd(self, fd, payload):
        pass

    def handle_FilterClear(self, fd, payload):
        pass

    def handle_MerkleBlock(self, fd, payload):
        pass

    def handle_Alert(self, fd, payload):
        pass

    def handle_SendHeaders(self, fd, payload):
        pass

    def handle_FeeFilter(self, fd, payload):
        pass

    def handle_SendCmpct(self, fd, payload):
        pass

    def handle_CmpctBlock(self, fd, payload):
        pass

    def handle_GetBlockTxn(self, fd, payload):
        pass

    def handle_BlockTxn(self, fd, payload):
        pass
