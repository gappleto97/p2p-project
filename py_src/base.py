"""A library to store common functions and protocol definitions"""

from __future__ import print_function
import bz2, hashlib, json, select, socket, struct, time, threading, traceback, uuid, zlib
from collections import namedtuple, deque

version = "0.2.1"
build_num = "build.117"

class flags():
    """A namespace to hold protocol-defined flags"""
    # main flags
    broadcast   = b'broadcast'  # also sub-flag
    waterfall   = b'waterfall'
    whisper     = b'whisper'    # also sub-flag
    renegotiate = b'renegotiate'

    # sub-flags
    handshake   = b'handshake'
    request     = b'request'
    response    = b'response'
    resend      = b'resend'
    peers       = b'peers'
    compression = b'compression'

    # compression methods
    gzip = b'gzip'
    bz2  = b'bz2'
    lzma = b'lzma'

user_salt    = str(uuid.uuid4()).encode()
compression = [flags.gzip, flags.bz2]  # This should be in order of preference. IE: gzip is best, then bz2, then none

try:
    import lzma
    compression.append(flags.lzma)
except:
    pass

# Utility method/class section; feel free to mostly ignore

base_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def to_base_58(i):  # returns bytes
    """Takes an integer and returns its corresponding base_58 string"""
    string = ""
    while i:
        string = base_58[i % 58] + string
        i = i // 58
    return string.encode()


def from_base_58(string):  # returns int (or long)
    """Takes a base_58 string and returns its corresponding integer"""
    decimal = 0
    if isinstance(string, bytes):
        string = string.decode()
    for char in string:
        decimal = decimal * 58 + base_58.index(char)
    return decimal


def getUTC():  # returns int
    """Returns the current unix time in UTC"""
    import calendar, time
    return calendar.timegm(time.gmtime())


def compress(msg, method):  # takes bytes, returns bytes
    """Shortcut method for compression"""
    if method == flags.gzip:
        return zlib.compress(msg)
    elif method == flags.bz2:
        return bz2.compress(msg)
    elif method == flags.lzma:
        return lzma.compress(msg)
    else:
        raise Exception('Unknown compression method')


def decompress(msg, method):  # takes bytes, returns bytes
    """Shortcut method for decompression"""
    if method == flags.gzip:
        return zlib.decompress(msg, zlib.MAX_WBITS | 32)
    elif method == flags.bz2:
        return bz2.decompress(msg)
    elif method == flags.lzma:
        return lzma.decompress(msg)
    else:
        raise Exception('Unknown decompression method')


def intersect(*args):  # returns list
    """Returns the ordered intersection of all given iterables, where the order is defined by the first iterable"""
    if not all(args):
        return []
    intersection = args[0]
    for l in args[1:]:
        intersection = [item for item in intersection if item in l]
    return intersection


def get_lan_ip():
    """Retrieves the LAN ip. Expanded from http://stackoverflow.com/a/28950776"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('8.8.8.8', 23))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.shutdown(socket.SHUT_RDWR)
        return IP


class protocol(namedtuple("protocol", ['subnet', 'encryption'])):
    """Defines service variables so that you can reject connections looking for a different service"""
    @property
    def id(self):
        h = hashlib.sha256(''.join([str(x) for x in self] + [version]).encode())
        return to_base_58(int(h.hexdigest(), 16))

default_protocol = protocol('', "Plaintext")  # PKCS1_v1.5")


class base_connection(object):
    """The base class for a connection"""
    def __init__(self, sock, server, prot=default_protocol, outgoing=False):
        self.sock = sock
        self.server = server
        self.protocol = prot
        self.outgoing = outgoing
        self.buffer = []
        self.id = None
        self.time = getUTC()
        self.addr = None
        self.compression = []
        self.last_sent = []
        self.expected = 4
        self.active = False

    def collect_incoming_data(self, data):
        """Collects incoming data"""
        if not bool(data):
            self.__print__(data, time.time(), level=5)
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            return False
        self.buffer.append(data)
        self.time = getUTC()
        if not self.active and self.find_terminator():
            self.__print__(self.buffer, self.expected, self.find_terminator(), level=4)
            self.expected = struct.unpack("!L", ''.encode().join(self.buffer))[0] + 4
            self.active = True
        return True

    def find_terminator(self):
        """Returns whether the definied return sequences is found"""
        return len(''.encode().join(self.buffer)) == self.expected

    def fileno(self):
        return self.sock.fileno()

    def __print__(self, *args, **kargs):
        """Private method to print if level is <= self.server.debug_level"""
        self.server.__print__(*args, **kargs)


class base_daemon(object):
    """The base class for a daemon"""    
    def __init__(self, addr, port, server, prot=default_protocol):
        self.protocol = prot
        self.server = server
        if self.protocol.encryption == "Plaintext":
            self.sock = socket.socket()
        elif self.protocol.encryption == "PKCS1_v1.5":
            import net
            self.sock = net.secure_socket(silent=True)
        else:
            raise Exception("Unknown encryption type")
        self.sock.bind((addr, port))
        self.sock.listen(5)
        self.sock.settimeout(0.1)
        self.exceptions = []
        self.alive = True
        self.daemon = threading.Thread(target=self.mainloop)
        self.daemon.daemon = True
        self.daemon.start()

    def __del__(self):
        self.alive = False

    def __print__(self, *args, **kargs):
        """Private method to print if level is <= self.server.debug_level"""
        self.server.__print__(*args, **kargs)


class base_socket(object):
    """The base class for a peer-to-peer socket"""
    def recv(self, quantity=1):
        """Receive 1 or several message objects. Returns none if none are present. Non-blocking."""
        if quantity != 1:
            ret_list = []
            while len(self.queue) and quantity > 0:
                ret_list.append(self.queue.pop())
                quantity -= 1
            return ret_list
        elif len(self.queue):
            return self.queue.pop()
        else:
            return None

    @property
    def status(self):
        """Returns "Nominal" if all is going well, or a list of unexpected (Excpetion, traceback) tuples if not"""
        return self.daemon.exceptions or "Nominal"   

    @property
    def outgoing(self):
        """IDs of outgoing connections"""
        return [handler.id for handler in self.routing_table.values() if handler.outgoing]

    @property
    def incoming(self):
        """IDs of incoming connections"""
        return [handler.id for handler in self.routing_table.values() if not handler.outgoing]

    def __print__(self, *args, **kargs):
        """Private method to print if level is <= self.__debug_level"""
        if kargs.get('level') <= self.debug_level:
            print(*args)

    def __del__(self):
        for key in self.routing_table:
            self.daemon.disconnect(self.routing_table[key])
        for handler in awaiting_ids:
            self.daemon.disconnect(handler)
        self.daemon.alive = False
        del self.daemon


class pathfinding_message(object):
    """An object used to build and parse protocol-defined message structures"""
    @classmethod
    def feed_string(cls, string, sizeless=False, compressions=None):
        """Constructs a pathfinding_message from a string or bytes object.
        Possible errors:
            AttributeError: Fed a non-string, non-bytes argument
            AssertionError: Initial size header is incorrect
            Exception:      Unrecognized compression method fed in compressions
            struct.error:   Packet headers are incorrect OR unrecognized compression
            IndexError:     See struct.error"""
        # First section checks size header
        string = cls.sanitize_string(string, sizeless)
        # Then we attempt to decompress
        string, compression_fail = cls.decompress_string(string, compressions)
        # After this, we process the packet size headers
        packets = cls.process_string(string)
        msg = cls(protocol, packets[0], packets[1], packets[4:], compression=compressions)
        msg.time = from_base_58(packets[3])
        msg.compression_fail = compression_fail
        return msg

    @classmethod
    def sanitize_string(cls, string, sizeless=False):
        """Removes the size header for further processing. Also checks if the header is valid.
        Possible errors:
            AttributeError: Fed a non-string, non-bytes argument
            AssertionError: Initial size header is incorrect"""
        if not isinstance(string, bytes):
            string = string.encode()
        if not sizeless:
            assert struct.unpack('!L', string[:4])[0] == len(string[4:]), \
                "Must assert struct.unpack('!L', string[:4])[0] == len(string[4:])"
            string = string[4:]
        return string

    @classmethod
    def decompress_string(cls, string, compressions=None):
        """Returns a tuple containing the decompressed bytes and a boolean as to whether decompression failed or not
        Possible errors:
            Exception:  Unrecognized compression method fed in compressions"""
        compression_fail = False
        for method in intersect(compressions, compression):  # second is module scope compression
            try:
                string = decompress(string, method)
                compression_fail = False
                break
            except:
                compression_fail = True
                continue
        return (string, compression_fail)

    @classmethod
    def process_string(cls, string):
        """Given a sanitized, plaintext string, returns a list of its packets
        Possible errors:
            struct.error:   Packet headers are incorrect OR not fed plaintext
            IndexError:     See struct.error"""
        processed, expected = 0, len(string)
        pack_lens, packets = [], []
        while processed != expected:
            pack_lens.extend(struct.unpack("!L", string[processed:processed+4]))
            processed += 4
            expected -= pack_lens[-1]
        # Then reconstruct the packets
        for index, length in enumerate(pack_lens):
            start = processed + sum(pack_lens[:index])
            end = start + length
            packets.append(string[start:end])
        return packets

    def __init__(self, protocol, msg_type, sender, payload, compression=None):
        self.protocol = protocol
        self.msg_type = msg_type
        self.sender = sender
        self.__payload = payload
        self.time = getUTC()
        if compression:
            self.compression = compression
        else:
            self.compression = []
        self.compression_fail = False

    @property
    def payload(self):
        """Returns a list containing the message payload encoded as bytes"""
        for i, val in enumerate(self.__payload):
            if not isinstance(val, bytes):
                self.__payload[i] = val.encode()
        return self.__payload

    @property
    def compression_used(self):
        """Returns the compression method this message is using"""
        for method in intersect(compression, self.compression):
            return method
        return None

    @property
    def time_58(self):
        """Returns the messages timestamp in base_58"""
        return to_base_58(self.time)

    @property
    def id(self):
        """Returns the message id"""
        payload_string = b''.join(self.payload)
        payload_hash = hashlib.sha384(payload_string + self.time_58)
        return to_base_58(int(payload_hash.hexdigest(), 16))

    @property
    def packets(self):
        """Returns the full list of packets in this message encoded as bytes, excluding the header"""
        meta = [self.msg_type, self.sender, self.id, self.time_58]
        for i, val in enumerate(meta):
            if not isinstance(val, bytes):
                meta[i] = val.encode()
        return meta + self.payload

    @property
    def __non_len_string(self):
        """Returns a bytes object containing the entire message, excepting the total length header"""
        packets = self.packets
        header = struct.pack("!" + str(len(packets)) + "L", 
                                    *[len(x) for x in packets])
        string = header + b''.join(packets)
        if self.compression_used:
            string = compress(string, self.compression_used)
        return string
    
    @property
    def string(self):
        """Returns a string representation of the message"""
        string = self.__non_len_string
        return struct.pack("!L", len(string)) + string

    def __len__(self):
        return len(self.__non_len_string)

    @property
    def len(self):
        """Return the struct-encoded length header"""
        return struct.pack("!L", self.__len__())


class message(object):
    """An object which gets returned to a user, containing all necessary information to parse and reply to a message"""
    def __init__(self, msg, server):
        if not isinstance(msg, pathfinding_message):
            raise TypeError("message must be passed a pathfinding_message")
        self.msg = msg
        self.server = server

    @property
    def time(self):
        """The time this message was sent at"""
        return self.msg.time    

    @property
    def sender(self):
        """The ID of this message's sender"""
        return self.msg.sender

    @property
    def protocol(self):
        """The protocol this message was sent under"""
        return self.msg.protocol
    
    @property
    def id(self):
        """This message's ID"""
        return self.msg.id

    @property
    def packets(self):
        """Return the message's component packets, including it's type in position 0"""
        return self.msg.payload

    def __len__(self):
        return self.msg.__len__()

    def __repr__(self):
        packets = self.packets
        string = "message(type=" + repr(packets[0]) + ", packets=" + repr(packets[1:]) + ", sender="
        if isinstance(self.sender, base_connection):  # This should no longer happen, but just in case
            return string + repr(self.sender.addr) + ")"
        else:
            return string + repr(self.sender) + ")"

    def reply(self, *args):
        """Replies to the sender if you're directly connected. Tries to make a connection otherwise"""
        if self.server.routing_table.get(self.sender):
            self.server.routing_table.get(self.sender).send(flags.whisper, flags.whisper, *args)
        else:
            request_hash = hashlib.sha384(self.sender + to_base_58(getUTC())).hexdigest()
            request_id = to_base_58(int(request_hash, 16))
            self.server.send(request_id, self.sender, type=flags.request)
            self.server.requests.update({request_id: [flags.whisper, flags.whisper] + list(args)})
            print("You aren't connected to the original sender. This reply is not guarunteed, but we're trying to make a connection and put the message through.")
