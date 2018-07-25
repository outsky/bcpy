import selectors
import socket
import time
import config
import lib
from structs import VarStr

sel = selectors.DefaultSelector()
slicedmsg = b""
sock = None

def sock_read(sock):
    data = sock.recv(4096)
    if data:
        on_recv(data)
    else:
        lib.info("disconnect: {}", sock)
        sel.unregister(sock)
        sock.close()

def sock_connect():
    global sock
    sock = socket.create_connection(("localhost", config.debug_port))
    sel.register(sock, selectors.EVENT_READ, sock_read)
    lib.info("connect to: {}", sock)

def on_recv(data):
    if slicedmsg and len(slicedmsg) > 0:
        data = slicedmsg + data
    while True:
        if not data or len(data) <= 0:
            break

        vs, size = VarStr.load(data)
        data = data[size:]
        lib.info("{}\n", vs.string.decode("utf-8"))

def send_cmd():
    cmd = input("> ")
    cmd = cmd.strip()
    if len(cmd) <= 0:
        return
    data = VarStr(cmd.encode("utf-8")).tobytes()
    sent = sock.send(data)

if __name__ == "__main__":
    sock_connect()
    while True:
        send_cmd()
        time.sleep(0.3)
        for key, _ in sel.select(0):
            key.data(key.fileobj)
