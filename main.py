# encoding: utf-8
import socket
import struct
import time
import random
import hashlib

def printb(bs):
    col = 0
    for b in bs:
        print("%.2X" % b, end = '')
        col += 1
        if col == 8:
            print("  ", end = '')
        elif col == 16:
            col = 0
            print("")
        else:
            print(" ", end = '')
    print("")

seed_addr = ("14.192.8.27", 21301)
#seed_addr = ("5.19.5.127", 8333)

def send_pong(sock, nonce):
    payload = struct.pack("<Q", nonce)
    h = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    checksum = h[:4]
    length = len(payload)
    msg = struct.pack("<I12sI4s{}s".format(length), 0xD9B4BEF9, b"verack", length, checksum, payload)
    sent = sock.send(msg)
    print("-> pong:{}/{}".format(sent, len(msg)))


def send_verack(sock):
    h = hashlib.sha256(hashlib.sha256(b"").digest()).digest()
    checksum = h[:4]
    msg = struct.pack("<I12sI4s", 0xD9B4BEF9, b"verack", 0, checksum)
    sent = sock.send(msg)
    print("-> verack:{}/{}".format(sent, len(msg)))

def send_version(sock):
    (ip_to, port_to) = sock.getpeername()
    (ip_from, port_from) = (sock.getsockname())

    # send version
    nonce = random.randint(1, 1000000000)
    now = int(time.time())

    services = 1
    ip_bytes = socket.inet_aton(ip_to)
    addr_to = struct.pack("<Q12s4sH", services, bytes.fromhex('0000 0000 0000 0000 0000 ffff'), ip_bytes, socket.htons(port_to))
    ip_bytes = socket.inet_aton(ip_from)
    addr_from = struct.pack("<Q12s4sH", services, bytes.fromhex('0000 0000 0000 0000 0000 ffff'), ip_bytes, socket.htons(port_from))

    version = struct.pack("<iQq26s26sQ16pi?", 70015, services, now, addr_to, addr_from, nonce, b"/Satoshi:0.7.2/", 212672, True)
    length = len(version)
    h = hashlib.sha256(hashlib.sha256(version).digest()).digest()
    checksum = h[:4]
    msg = struct.pack("<I12sI4s{}s".format(length), 0xD9B4BEF9, b"version", length, checksum, version)

    sent = sock.send(msg)
    print("-> version:{}/{}".format(sent, len(msg)))

def parse_version(sock, data):
    common = data[:46]
    data = data[46:]
    (version, services, timestamp, addr_recv) = struct.unpack("<iQq26s", common)
    if version >= 106:
        if version >= 70001:
            strlen = len(data) - 26 - 8 - 4 - 1
            (addr_from, nonce, user_agent, start_height, relay) = struct.unpack("<26sQ{}pi?".format(strlen), data)
        else:
            strlen = len(data) - 26 - 8 - 4
            (addr_from, nonce, user_agent, start_height) = struct.unpack("<26sQ{}pi".format(strlen), data)
    print("<- version:\nversion:{}\nservices:{}\ntimestamp:{}\nnonce:{}\nuser agent:{}\nstart height:{}\nrelay:{}\n".format(version,
        services, timestamp, nonce, user_agent, start_height, relay))
    send_verack(sock)

def parse_ping(sock, data):
    (nonce,) = struct.unpack("<Q", data)
    print("<- ping:\nnonce:{}\n".format(nonce))
    send_pong(sock, nonce)

def get_varint(data):
    ints = data[:1]
    (n, ) = struct.unpack("<B", ints)
    count = 0
    size = 0
    if n < 0xFD:
        count = n
        size = 1
    elif n == 0xFD:
        ints = data[1:3]
        (count, ) = struct.unpack("<H", ints)
        size = 3
    elif n == 0xFE:
        ints = data[1:5]
        (count, ) = struct.unpack("<I", ints)
        size = 5
    elif n == 0xFF:
        ints = data[1:9]
        (count, ) = struct.unpack("<Q", ints)
        size = 9

    return (count, size)


def parse_getheaders(sock, data):
    ints = data[:4]
    data = data[4:]
    (version, ) = struct.unpack("<I", ints)

    (count, size) = get_varint(data)
    print(count, size)
    data = data[size:]

    print("<- getheaders:\nversion:{}\nhash count:{}".format(version, count))

    print("data len:", len(data), count*32+32)

    for i in range(count):
        hashs = data[:32]
        data = data[32:]
        (hlocator, ) = struct.unpack("<32s", hashs)
        print("{}:\t{}".format(i, hlocator))

    (hstop, ) = struct.unpack("<32s", hashs)
    print("hash stop:{}\n".format(hstop))

def parse_addr(sock, data):
    (count, size) = get_varint(data)
    data = data[size:]
    print("<- addr:\ncount:{}".format(count))

    for i in range(count):
        (timestamp, addr) = struct.unpack("<I26s", data)
        print("{}:\ttimestamp:{}, addr:{}".format(i, timestamp, addr))


def parse_msg(sock, msg):
    while len(msg) > 0:
        header = msg[:24]
        (magic, command, length, checksum) = struct.unpack("<I12sI4s", header)
        if length + 24 > len(msg):
            return msg

        msg = msg[24:]
        payload = msg[:length]
        msg = msg[length:]

        command = command.decode('utf-8')
        print("===", command, length, len(payload), len(msg))
        if command[:len("version")] == "version":
            parse_version(sock, payload)
        elif command[:len("verack")] == "verack":
            print("<verack>:\nmagic:{}\ncommand:{}\nlength:{}\nchecksum:{}\n".format(magic, command, length, checksum))
        elif command[:len("ping")] == "ping":
            parse_ping(sock, payload)
        elif command[:len("addr")] == "addr":
            parse_addr(sock, payload)
        elif command[:len("getheaders")] == "getheaders":
            parse_getheaders(sock, payload)
        else:
            print("unknown command: <{}>".format(command))


if __name__ == "__main__":
    sock = socket.create_connection(seed_addr)
    send_version(sock)

    slicedmsg = b""

    for i in range(15):
        print("-----", i)
        # recv verack
        data = sock.recv(40960)
        if slicedmsg and len(slicedmsg) > 0:
            data = slicedmsg + data
        if data and len(data) > 0:
            slicedmsg = parse_msg(sock, data)

