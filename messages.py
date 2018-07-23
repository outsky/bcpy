# coding=utf-8

import struct
import time
import config
import lib
from structs import *

class m_version:
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
        ret = m_version(0)
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
        lib.debug("<version>\nversion:{}\nservices:{}\ntimestamp:{}\nnonce:{}\nuser agent:{}\nstart height:{}\nrelay:{}\n".format(self.version,
            self.services, self.timestamp, self.nonce, self.user_agent, self.start_height, self.relay))


class m_verack:
    def __init__(self):
        pass

    def tobytes(self):
        return b""

    @staticmethod
    def load(data):
        return m_verack()

    def debug(self):
        lib.debug("<verack> no extra data\n")

class m_ping:
    def __init__(self):
        self.nonce = lib.random64()

    def tobytes(self):
        return struct.pack("<Q", self.nonce)

    @staticmethod
    def load(data):
        ret = m_ping()
        (ret.nonce, ) = struct.unpack("<Q", data)
        return ret

    def debug(self):
        lib.debug("<ping>\nnonce: {}\n".format(self.nonce))

class m_pong:
    def __init__(self, nonce):
        self.nonce = nonce

    def tobytes(self):
        return struct.pack("<Q", self.nonce)

    @staticmethod
    def load(data):
        ret = m_pong()
        (ret.nonce, ) = struct.unpack("<Q", data)
        return ret

    def debug(self):
        lib.debug("<pong>\nnonce: {}\n".format(self.nonce))

class m_addr:
    def __init__(self, addr_list):
        self.addr_list = addr_list

    def tobytes(self):
        pass

    @staticmethod
    def load(data):
        (varint, size) = s_varint.load(data)
        data = data[size:]
        count = varint.value

        addr_list = []
        for i in range(count):
            entry = struct.unpack("<I26s", data)
            addr_list.append(entry)
        return m_addr(addr_list)

    def debug(self):
        s = "<addr>\ncount:{}\n".format(len(self.addr_list))
        for (i, entry) in enumerate(self.addr_list):
            s += "{}:\ttimestamp:{}, addr:{}\n".format(i, entry[0], entry[1])
        lib.debug(s)

class m_getheaders:
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

        (varint, size) = s_varint.load(data)
        count = varint.value
        data = data[size:]

        locators = []
        for i in range(count):
            locators.append(data[:32])
            data = data[32:]
        return m_getheaders(locators, data[:32])

    def debug(self):
        s = "<getheaders>\nversion:{}\nlocator hash count:{}\n".format(self.version, len(self.locators))
        for (i, h) in enumerate(self.locators):
            s += "{}:\t{}\n".format(i, h)
        s += "hash stop: "
        s += str(self.stop)
        lib.debug(s)