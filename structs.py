# coding=utf-8
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
            lib.err("<{}> checksum failed: {}, {}".format(command, checksum, msg.checksum))

        return (msg, data, None)

    def tobytes(self):
        return struct.pack("<I12sI4s{}s".format(self.length), self.magic, self.command.encode("utf-8"),
            self.length, self.checksum, self.payload)


class s_varint:
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
        return (s_varint(value), size)

    def tobytes(self):
        pass # TODO:

class s_varstr:
    pass

class s_netaddr:
    pass

class s_inv_vect:
    pass

class s_blockheaders:
    pass

