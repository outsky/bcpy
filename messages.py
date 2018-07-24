import socket
import struct
import time
import config
import lib
from structs import *

class Version:
    def __init__(self, start_height):
        self.version = config.version
        self.services = config.services
        self.timestamp = int(time.time())
        self.addr_recv = config.addr
        self.addr_from = config.addr
        self.nonce = lib.random64()
        self.user_agent = config.user_agent
        self.start_height = start_height
        self.relay = config.relay

    def tobytes(self):
        return struct.pack("<iQq26s26sQ16pi?", self.version, self.services, self.timestamp, self.addr_recv, self.addr_from, 
            self.nonce, self.user_agent, self.start_height, self.relay)

    @staticmethod
    def load(data):
        ret = Version(0)
        common = data[:46]
        data = data[46:]
        (ret.version, ret.services, ret.timestamp, ret.addr_recv) = struct.unpack("<iQq26s", common)
        if ret.version >= 106:
            if ret.version >= 70001:
                strlen = len(data) - 26 - 8 - 4 - 1
                (ret.addr_from, ret.nonce, ret.user_agent, ret.start_height, ret.relay) = struct.unpack("<26sQ{}pi?".format(strlen), data)
            else:
                strlen = len(data) - 26 - 8 - 4
                (ret.addr_from, ret.nonce, ret.user_agent, ret.start_height) = struct.unpack("<26sQ{}pi".format(strlen), data)
        return ret
        
    def debug(self):
        lib.debug("<version>\nversion:{}\nservices:{}\ntimestamp:{}\nnonce:{}\nuser agent:{}\nstart height:{}\nrelay:{}\n", self.version,
            self.services, self.timestamp, self.nonce, self.user_agent, self.start_height, self.relay)


class VerAck:
    def __init__(self):
        pass

    def tobytes(self):
        return b""

    @staticmethod
    def load(data):
        return VerAck()

    def debug(self):
        lib.debug("<verack> no extra data\n")

class Ping:
    def __init__(self):
        self.nonce = lib.random64()

    def tobytes(self):
        return struct.pack("<Q", self.nonce)

    @staticmethod
    def load(data):
        ret = Ping()
        if len(data) == 8:
            (ret.nonce, ) = struct.unpack("<Q", data)
        return ret

    def debug(self):
        lib.debug("<ping>\nnonce: {}\n", self.nonce)

class Pong:
    def __init__(self, nonce):
        self.nonce = nonce

    def tobytes(self):
        return struct.pack("<Q", self.nonce)

    @staticmethod
    def load(data):
        ret = Pong()
        (ret.nonce, ) = struct.unpack("<Q", data)
        return ret

    def debug(self):
        lib.debug("<pong>\nnonce: {}\n", self.nonce)

class GetAddr:
    def __init__(self):
        pass

    def tobytes(self):
        return b""

    @staticmethod
    def load(data):
        return GetAddr()

    def debug(self):
        lib.debug("<getaddr> no extra data\n")

class Addr:
    def __init__(self, addr_list):
        self.addr_list = addr_list

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (varint, size) = VarInt.load(data)
        data = data[size:]
        count = varint.value

        addr_list = []
        for i in range(count):
            (addr, size) = NetAddr.load(data)
            data = data[size:]
            addr_list.append(addr)
        return Addr(addr_list)

    def debug(self):
        s = "<addr>\ncount:{}\n".format(len(self.addr_list))
        for (i, addr) in enumerate(self.addr_list):
            s += "{}:\ttime:{}, services:{}, ip:{}, port:{}\n".format(i, addr.time, addr.services, socket.inet_ntoa(addr.ip[-4:]), addr.port)
        lib.debug(s)

class GetHeaders:
    def __init__(self, locators, stop):
        self.version = config.version
        self.locators = locators
        self.stop = stop

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (version, ) = struct.unpack("<I", data[:4])
        data = data[4:]

        (varint, size) = VarInt.load(data)
        count = varint.value
        data = data[size:]

        locators = []
        for i in range(count):
            locators.append(data[:32])
            data = data[32:]
        return GetHeaders(locators, data[:32])

    def debug(self):
        s = "<getheaders>\nversion:{}\nlocator hash count:{}\n".format(self.version, len(self.locators))
        for (i, h) in enumerate(self.locators):
            s += "{}:\t{}\n".format(i, h)
        s += "hash stop: "
        s += str(self.stop)
        lib.debug(s)

class Inv:
    def __init__(self, inventory):
        self.inventory = inventory

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (varint, size) = VarInt.load(data)
        data = data[size:]

        inventory = []
        for i in range(varint.value):
            (iv, size) = InvVect.load(data)
            data = data[size:]
            inventory.append(iv)
        return Inv(inventory)

    def debug(self):
        s = "<inv>\ncount:{}\n".format(len(self.inventory))
        for (i, iv) in enumerate(self.inventory):
            s += "{}:\t{}\t{}\n".format(i, iv.type, iv.hash)
        lib.debug(s)

class SendHeaders:
    def __init__(self):
        pass

    def tobytes(self):
        return b""

    @staticmethod
    def load(data):
        return SendHeaders()

    def debug(self):
        lib.debug("<sendheaders> no extra data\n")

class SendCmpct:
    def __init__(self, n1, n2):
        self.n1 = n1
        self.n2 = n2

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (n1, n2) = struct.unpack("<BQ", data)
        return SendCmpct(n1, n2)

    def debug(self):
        lib.debug("<sendcmpct>\nn1: {}\nn2:{}\n", self.n1, self.n2)

class Reject:
    def __init__(self, message, ccode, reason, data):
        self.message = message
        self.ccode = ccode
        self.reason = reason
        self.data = data

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (message, size) = VarStr.load(data)
        data = data[size:]

        (ccode, ) = struct.unpack("<B", data[:1])

        (reason, size) = VarStr.load(data)
        data = data[size:]
        return Reject(message, ccode, reason, data)

    def debug(self):
        lib.debug("<reject>\nmessage:{}\nccode:{}\nreason:{}\ndata:{}\n", self.message, self.ccode, self.reason, self.data)

class FeeFilter:
    def __init__(self, feerate):
        self.feerate = feerate

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (feerate, ) = struct.unpack("<Q", data)
        return FeeFilter(feerate)

    def debug(self):
        lib.debug("<feefilter>\nfeerate:{}\n", self.feerate)
