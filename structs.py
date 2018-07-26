import config
import lib
import struct
import hashlib

class Message:
    def __init__(self, command, payload, magic = config.magic):
        self.magic = magic
        self.command = command
        self.payload = payload
        self.length = len(self.payload)
        self.checksum = lib.double_hash(self.payload)[:4]

    @staticmethod
    # ret: (msg, data, slicedmsg)
    def load(data):
        datalen = len(data)
        if datalen < 24:
            return (None, None, data)
        (magic, command, length, checksum) = struct.unpack("<I12sI4s", data[:24])
        if length + 24 > datalen:
            return (None, None, data)

        data = data[24:]
        payload = data[:length]
        data = data[length:]

        command = command.decode("utf-8").rstrip("\x00")
        msg = Message(command, payload, magic)
        if checksum != msg.checksum:
            lib.err("<{}> checksum failed: {}, {}", command, checksum, msg.checksum)

        return (msg, data, None)

    def tobytes(self):
        return struct.pack("<I12sI4s{}s".format(self.length), self.magic, self.command.encode("utf-8"),
            self.length, self.checksum, self.payload)

# 1st byte: size
class CompressInt:
    def __init__(self, value):
        self.value = value

    @staticmethod
    def load(data):
        pass

    def tobytes(self):
        pass

class VarInt:
    def __init__(self, value):
        self.value = value

    @staticmethod
    def load(data):
        (n, ) = struct.unpack("<B", data[:1])
        value = 0
        size = 0
        if n < 0xFD:
            value = n
            size = 1
        elif n == 0xFD:
            (value, ) = struct.unpack("<H", data[1:3])
            size = 3
        elif n == 0xFE:
            (value, ) = struct.unpack("<I", data[1:5])
            size = 5
        elif n == 0xFF:
            (value, ) = struct.unpack("<Q", data[1:9])
            size = 9
        return (VarInt(value), size)

    def tobytes(self):
        if self.value < 0xFD:
            return struct.pack("<B", self.value)
        elif self.value <= 0xFFFF:
            return b'\xFD' + struct.pack("<H", self.value)
        elif self.value <= 0xFFFFFFFF:
            return b'\xFE' + struct.pack("<I", self.value)
        else:
            return b'\xFF' + struct.pack("<Q", self.value)

class VarStr:
    def __init__(self, string):
        self.string = string # bytes

    @staticmethod
    def load(data):
        varint, size = VarInt.load(data)
        data = data[size:]
        string = data[:varint.value]
        return (VarStr(string), size + varint.value)

    def tobytes(self):
        vi = VarInt(len(self.string))
        vib = vi.tobytes()
        return vib + self.string

    def __str__(self):
        return "{}({})".format(self.string, len(self.string))

class NetAddr:
    def __init__(self, time, services, ip, port):
        self.time = time
        self.services = services
        self.ip = ip
        self.port = port

    @staticmethod
    def load(data, from_version = False):
        size = 30
        time = 0
        if from_version:
            size = 26
            (services, ip, port) = struct.unpack("<Q16sH", data[:size])
        else:
            (time, services, ip, port) = struct.unpack("<IQ16sH", data[:size])
        return (NetAddr(time, services, ip, port), size)

    def tobytes(self, to_version = False):
        if to_version:
            return struct.pack("<Q16sH", self.services, self.ip, self.port)
        else:
            return struct.pack("<IQ16sH", self.time, self.services, self.ip, self.port)

class InvVect:
    def __init__(self, type, hash):
        self.type = type
        self.hash = hash

    @staticmethod
    def load(data):
        size = 36
        type, hash = struct.unpack("<I32s", data[:size])
        return (InvVect(type, hash), size)

    def tobytes(self):
        pass

class BlockHeader:
    def __init__(self, version, prev, merkle, timestamp, bits, nonce):
        self.version = version
        self.prev = prev
        self.merkle = merkle
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    @staticmethod
    def load(data):
        version, prev, merkle, timestamp, bits, nonce = struct.unpack("<i32s32sIII", data[:80])
        data = data[80:]
        vi, size = VarInt.load(data)
        return (BlockHeader(version, prev, merkle, timestamp, bits, nonce, vi.value), 80 + size)

    def tobytes(self):
        return struct.pack("<i32s32sIII", self.version, self.prev, self.merkle, self.timestamp, 
            self.bits, self.nonce)

class Block:
    def __init__(self, header, txs):
        self.header = header
        self.txs = txs

    @staticmethod
    def load(data):
        totalsize = 0
        (size, ) = struct.unpack("<I", data[:4])
        totalsize += 4
        data = data[4:]

        header, size = BlockHeader.load(data)
        totalsize += size
        data = data[size:]

        vi, size = VarInt.load(data)
        totalsize += size
        data = data[size:]

        txs = []
        for _ in range(vi.value):
            tx, size = Tx.load(data)
            totalsize += size
            data = data[size:]
            txs.append(tx)

        return (Block(header, txs), totalsize)

    def tobytes(self):
        ret = self.header.tobytes()
        ret += VarInt(len(self.txs)).tobytes()
        for tx in self.txs:
            ret += tx.tobytes()
        return ret

class TxIn:
    def __init__(self, prev, script, sequence):
        self.prev = prev
        self.script = script
        self.sequence = sequence

    @staticmethod
    def load(data):
        totalsize = 0
        prev, size = OutPoint.load(data)
        totalsize += size
        data = data[size:]

        script, size = VarStr.load(data)
        totalsize += size
        data = data[size:]

        sequence = struct.unpack("<I", data[:4])
        totalsize += 4
        return (TxIn(prev, script, sequence), totalsize)

    def tobytes(self):
        return self.prev.tobytes() + self.script.tobytes() + struct.pack("<I", self.sequence)

class TxOut:
    def __init__(self, value, script):
        self.value = value
        self.script = script

    @staticmethod
    def load(data):
        (value, ) = struct.unpack("<Q", data[:8])
        data = data[8:]

        vs, size = VarStr.load(data)
        return (TxOut(value, vs), 8 + size)

    def tobytes(self):
        return struct.pack("<Q", self.value) + self.script.tobytes()

class OutPoint:
    def __init__(self, hash, index):
        self.hash = hash
        self.index = index

    @staticmethod
    def load(data):
        hash, index = struct.unpack("<32sI", data[:36])
        return (OutPoint(hash, index), 36)

    def tobytes(self):
        return struct.pack("<32sI", self.hash, self.index)

class Witness:
    def __init__(self, witnesses):
        self.witnesses = witnesses

    @staticmethod
    def load(data):
        totalsize = 0
        (vi, size) = VarInt.load(data)
        totalsize += size
        data = data[size:]

        witnesses = []
        for _ in range(vi.value):
            (vs, size) = VarStr.load(data)
            totalsize += size
            data = data[size:]
            witnesses.append(vs)
        return (Witness(witnesses), totalsize)

    def tobytes(self):
        ret = VarInt(len(self.witnesses)).tobytes()
        for w in self.witnesses:
            ret += w.tobytes()
        return ret
