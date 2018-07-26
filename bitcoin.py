import selectors
import socket
import config
from structs import *
from messages import *
import lib
from db import DataBase

class Node:
    def __init__(self, sock, debug = False):
        self.sock = sock
        self.slicedmsg = b""
        self.debug = debug # debug node
        self.version = 0
        self.services = 0
        self.user_agent = ""
        self.start_height = 0

    def __str__(self):
        return "sock: {}\ndebug: {}\nversion: {}\nservices: {}\nuser agent: {}\nstart height: {}\n".format(
            self.sock, self.debug, self.version, self.services, self.user_agent, self.start_height)

class BitCoin:
    def __init__(self):
        self.nodes = {}
        self.db = DataBase(config.db_name)
        if len(self.db.keys()) <= 0:
            if not self.create_genesis_block():
                exit()

        self.sel = selectors.DefaultSelector()
        self.sock_listen(config.listen_port)
        self.sock_listen(config.debug_port)
        self.sock_connect(config.seed_addr)

    def create_genesis_block(self):
        txin = []
        prev = OutPoint(b"", 0xFFFFFFFF)
        script = VarInt(486604799).tobytes() + VarInt(4).tobytes() + VarStr(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks").tobytes()
        txin.append(TxIn(prev, VarStr(script), 0xFFFFFFFF))

#        lib.printb(TxIn(prev, VarStr(script), 0xFFFFFFFF).tobytes())
        lib.printb(script)
        return False

        txout = []
        script = VarStr(lib.hexstr2bytes("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")).tobytes() + struct.pack("<B", 0xAC)
        txout.append(TxOut(50 * config.coin, VarStr(script)))

        txs = []
        txs.append(Tx(1, 0, txin, txout, [], 0))

        merkle = lib.merkle_root(txs)
        if merkle != lib.hexstr2bytes("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"):
            lib.err("create genesis block failed: merkle root err {}", merkle.hex())
            #return False

        header = BlockHeader(1, b"", merkle, 1231006505, 0x1d00ffff, 2083236893)
        key = lib.double_hash(header.tobytes())
        if key != lib.hexstr2bytes("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"):
            lib.err("create genesis block failed: hash err {}", key.hex())
            #return False

        b = Block(header, txs)
        lib.printb(b.tobytes())
        #self.db.add(key, b.tobytes())
        lib.debug("genesis block created")
        #return True
        return False

    def sock_accept(self, sock):
        conn, addr = sock.accept()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.sock_read)

        _, port = conn.getsockname()
        debug = port == config.debug_port

        fd = conn.fileno()
        self.nodes[fd] = Node(conn, debug)
        lib.info("new connection: {}({}), debug: {}", addr, fd, debug)

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
        self.send_msg(fd, msg)

    def sock_listen(self, port):
        sock = socket.socket()
        sock.bind(("localhost", port))
        sock.listen()
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, self.sock_accept)

    def run(self):
        while True:
            for key, _ in self.sel.select():
                key.data(key.fileobj)

    def on_recv(self, fd, data):
        node = self.nodes[fd]
        if node.slicedmsg and len(node.slicedmsg) > 0:
            data = node.slicedmsg + data
        while True:
            if not data or len(data) <= 0:
                break

            if node.debug:
                vs, size = VarStr.load(data)
                data = data[size:]
                self.debug(fd, vs.string.decode("utf-8"))
            else:
                (msg, data, node.slicedmsg) = Message.load(data)
                if not msg:
                    break
                self.handle(fd, msg)

    def debug(self, fd, cmd):
        lib.info("dbg: {}\n", cmd)
        handler = getattr(self, "debug_" + cmd, None)
        if not handler:
            err = "unknown debug cmd <{}>".format(cmd)
            lib.err(err)
            self.send_debug_msg(fd, err)
            return
        handler(fd)

    def send_debug_msg(self, fd, string):
        node = self.nodes[fd]
        data = VarStr(string.encode("utf-8")).tobytes()
        sent = node.sock.send(data)
        lib.info("-> dbg:{}/{}", sent, len(data))

    def send_msg(self, fd, msg):
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
        node = self.nodes[fd]
        node.version = payload.version
        node.services = payload.services
        node.user_agent = payload.user_agent
        node.start_height = payload.start_height

        msg = Message("verack", VerAck().tobytes())
        self.send_msg(fd, msg)

    def handle_VerAck(self, fd, payload):
        node = self.nodes[fd]
        ip, _ = node.sock.getsockname()
        msg = Message("addr", Addr([NetAddr(int(time.time()), config.services, socket.inet_pton(node.sock.family, ip), config.listen_port)]).tobytes())
        self.send_msg(fd, msg)

        msg = Message("getaddr", GetAddr().tobytes())
        self.send_msg(fd, msg)
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
        self.send_msg(fd, msg)

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

    # debug handlers
    def debug_nodes(self, fd):
        msg = ""
        for k, v in self.nodes.items():
            msg += "{}:\n{}\n".format(k, v)
        self.send_debug_msg(fd, msg)
