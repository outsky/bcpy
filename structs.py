import config
import lib
import struct
import hashlib

class s_message:
    def __init__(self, command, payload, magic = config.magic):
        self.magic = magic
        self.command = command
        self.payload = payload
        self.length = len(self.payload)
        self.checksum = hashlib.sha256(hashlib.sha256(self.payload).digest()).digest()[:4]

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

        command = command.decode("utf-8")
        msg = s_message(command, payload, magic)
        if checksum != msg.checksum:
            lib.err("<{}> checksum failed: {}, {}", command, checksum, msg.checksum)

        return (msg, data, None)

    def tobytes(self):
        return struct.pack("<I12sI4s{}s".format(self.length), self.magic, self.command.encode("utf-8"),
            self.length, self.checksum, self.payload)


class s_var_int:
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
        return (s_var_int(value), size)

    def tobytes(self):
        pass # TODO:

class s_var_str:
    def __init__(self, length, string):
        self.length = length
        self.string = string

    @staticmethod
    def load(data):
        (varint, size) = s_var_int.load(data)
        data = data[size:]
        string = data[:varint.value]
        return (s_var_str(varint.value, string), size + varint.value)

    def tobytes(self):
        pass

    def __str__(self):
        return "{}({})".format(self.string, self.length)

class s_net_addr:
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
        return (s_net_addr(time, services, ip, port), size)

    def tobytes(self, to_version = False):
        if to_version:
            return struct.pack("<Q16sH", self.services, self.ip, self.port)
        else:
            return struct.pack("<IQ16sH", self.time, self.services, self.ip, self.port)

class s_inv_vect:
    def __init__(self, type, hash):
        self.type = type
        self.hash = hash

    @staticmethod
    def load(data):
        size = 36
        (type, hash) = struct.unpack("<I32s", data[:size])
        return (s_inv_vect(type, hash), size)

    def tobytes(self):
        pass

class s_blockheaders:
    pass

