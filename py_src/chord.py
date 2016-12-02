from __future__ import print_function
from __future__ import absolute_import

import hashlib
import json
import random
import select
import socket
import struct
import sys
import time
import traceback
import warnings

try:
    from .cbase import protocol
except:
    from .base import protocol

from .base import (
    flags, compression, to_base_58, from_base_58, base_connection, message,
    base_daemon, base_socket, InternalMessage, json_compressions)
from .utils import (getUTC, get_socket, intersect, awaiting_value, most_common)

default_protocol = protocol('chord', "Plaintext")  # SSL")
hashes = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']

if sys.version_info >= (3,):
    xrange = range


def distance(a, b, limit):
    """This is a clockwise ring distance function.
    It depends on a globally defined k, the key size.
    The largest possible node id is limit (or 2**k).
    """
    return (b - a) % limit


class chord_connection(base_connection):
    """The class for chord connection abstraction.
    This inherits from :py:class:`py2p.base.base_connection`
    """
    def found_terminator(self):
        """This method is called when the expected amount of data is received

        Returns:
            ``None``
        """
        try:
            msg = super(chord_connection, self).found_terminator()
        except (IndexError, struct.error):
            self.__print__(
                "Failed to decode message: %s. Expected compression: %s."
                % (raw_msg, intersect(compression, self.compression)[0]),
                level=1)
            self.send(flags.renegotiate, flags.compression, json.dumps([]))
            self.send(flags.renegotiate, flags.resend)
            return
        packets = msg.packets
        self.__print__("Message received: %s" % packets, level=1)
        if self.handle_renegotiate(packets):
            return
        self.server.handle_msg(message(msg, self.server), self)

    @property
    def id_10(self):
        """Returns the nodes ID as an integer"""
        return from_base_58(self.id)

    def __hash__(self):
        return self.id_10 or id(self)


class chord_daemon(base_daemon):
    """The class for chord daemon.
    This inherits from :py:class:`py2p.base.base_daemon`
    """
    def mainloop(self):
        """Daemon thread which handles all incoming data and connections"""
        while self.main_thread.is_alive() and self.alive:
            conns = (list(self.server.routing_table.values())
                     + self.server.awaiting_ids)
            for handler in select.select(conns + [self.sock], [], [], 0.01)[0]:
                if handler == self.sock:
                    self.handle_accept()
                else:
                    self.process_data(handler)
            for handler in conns:
                self.kill_old_nodes(handler)
            self.server.update_fingers()

    def handle_accept(self):
        """Handle an incoming connection"""
        if sys.version_info >= (3, 3):
            exceptions = (socket.error, ConnectionError)
        else:
            exceptions = (socket.error, )
        try:
            conn, addr = self.sock.accept()
            self.__print__('Incoming connection from %s' % repr(addr), level=1)
            handler = chord_connection(conn, self.server)
            handler.sock.settimeout(1)
            self.server.awaiting_ids.append(handler)
        except exceptions:
            pass

    def process_data(self, handler):
        """Collects incoming data from nodes"""
        try:
            while not handler.find_terminator():
                if not handler.collect_incoming_data(handler.sock.recv(1)):
                    self.__print__(
                        "disconnecting node %s while in loop" % handler.id,
                        level=6)
                    self.server.disconnect(handler)
                    return
            handler.found_terminator()
        except socket.timeout:  # pragma: no cover
            return  # Shouldn't happen with select, but if it does...
        except Exception as e:
            if (isinstance(e, socket.error) and
                    e.args[0] in (9, 104, 10053, 10054, 10058)):
                node_id = handler.id
                if not node_id:
                    node_id = repr(handler)
                self.__print__(
                    "Node %s has disconnected from the network" % node_id,
                    level=1)
            else:
                self.__print__(
                    "There was an unhandled exception with peer id %s. This "
                    "peer is being disconnected, and the relevant exception "
                    "is added to the debug queue. If you'd like to report th"
                    "is, please post a copy of your chord_socket.status to g"
                    "ithub.com/gappleto97/p2p-project/issues." % handler.id,
                    level=0)
                self.exceptions.append((e, traceback.format_exc()))
            self.server.disconnect(handler)


class chord_socket(base_socket):
    """The class for chord socket abstraction.
    This inherits from :py:class:`py2p.base.base_socket`
    """
    def __init__(self, addr, port, k=6, prot=default_protocol, out_addr=None,
                 debug_level=0):
        """Initializes a chord socket

        Args:
            addr:           The address you wish to bind to (ie: "192.168.1.1")
            port:           The port you wish to bind to (ie: 44565)
            k:              This number indicates the node counts the network
                                can support. You must have > (k+1) nodes.
                                You may only have up to 2**k nodes, but at
                                that count you will likely get ID conflicts.
            prot:           The protocol you wish to operate over, defined by
                                a :py:class:`py2p.base.protocol` object
            out_addr:       Your outward facing address. Only needed if you're
                                connecting over the internet. If you use
                                '0.0.0.0' for the addr argument, this will
                                automatically be set to your LAN address.
            debug_level:    The verbosity you want this socket to use when
                                printing event data

        Raises:
            socket.error:   The address you wanted could not be bound, or is
                                otherwise used
        """
        super(chord_socket, self).__init__(
            addr, port, prot, out_addr, debug_level)
        self.k = k  # 160  # SHA-1 namespace
        self.limit = 2**k
        self.id_10 = from_base_58(self.id) % self.limit
        self.id = to_base_58(self.id_10)
        self.data = dict(((method, dict()) for method in hashes))
        self.daemon = chord_daemon(addr, port, self)
        self.requests = {}
        self.predecessors = []
        self.register_handler(self.__handle_handshake)
        self.register_handler(self.__handle_peers)
        self.register_handler(self.__handle_response)
        self.register_handler(self.__handle_request)
        self.register_handler(self.__handle_retrieve)
        self.register_handler(self.__handle_store)
        self.next = self
        self.prev = self
        self.leeching = True
        warnings.warn(
            "This network configuration supports %s total nodes and requires"
            " a theoretical minimum of %s nodes"
            % (min(self.limit, 2**160), self.k), RuntimeWarning, stacklevel=2)

    @property
    def addr(self):
        """An alternate binding for ``self.out_addr``, in order to better
        handle self-references in the daemon thread
        """
        return self.out_addr

    def __findFinger__(self, key):
        current = self
        for x in xrange(self.k):
            if (distance(current.id_10, key, self.limit)
                    > distance(self.routing_table.get(x, self).id_10, key,
                               self.limit)):
                current = self.routing_table.get(x, self)
        return current

    def __get_fingers(self):
        """Returns a finger table for your peer"""
        peer_list = list(set((
            (tuple(node.addr), node.id.decode()) for node in
            list(self.routing_table.values()) + self.awaiting_ids if node.addr
        )))
        if self.next is not self:
            peer_list.append((self.next.addr, self.next.id.decode()))
        if self.prev is not self:
            peer_list.append((self.prev.addr, self.prev.id.decode()))
        return peer_list

    def set_fingers(self, handler):
        """Given a handler, check to see if it's the closest connection to an
        ideal slot.

        In other words, if it's the closest ID you know of to a power of two
        distance from you, add it to your connection table.

        Args:
            handler: A :py:class:`~py2p.chord.chord_connection`
        """
        for x in xrange(self.k):
            goal = self.id_10 + 2**x
            if (distance(self.__findFinger__(goal).id_10, goal, self.limit)
                    > distance(handler.id_10, goal, self.limit)):
                former = self.__findFinger__(goal)
                self.routing_table[x] = handler
                if former not in self.routing_table.values():
                    self.disconnect(former)

    def is_saturated(self):
        """Returns whether all ideal connection slots are filled"""
        for x in xrange(self.k):
            node = self.__findFinger__(self.id_10 + 2**x % self.limit)
            if distance(node.id_10, self.id_10 + 2**x, self.limit) != 0:
                return False
        return True

    def update_fingers(self):
        """Updates your connection table, and sends a request for more peers
        whenever ``getUTC() % 5 == 0 and not self.is_saturated()``

        Is this efficient? No.

        Will it be fixed? Yes. See the warning up top.
        """
        should_request = ((not self.leeching) and (not (getUTC() % 5))
                          and (not self.is_saturated()))
        for handler in (list(self.routing_table.values())
                        + self.awaiting_ids + self.predecessors):
            if handler.id:
                self.set_fingers(handler)
            if should_request:
                handler.send(flags.whisper, flags.request, b'*')

    def handle_msg(self, msg, conn):
        """Decides how to handle various message types, allowing some to be
        handled automatically
        """
        if not super(chord_socket, self).handle_msg(msg, conn):
            self.__print__("Ignoring message with invalid subflag", level=4)

    def __handle_handshake(self, msg, handler):
        """This callback is used to deal with handshake signals. Its two
        primary jobs are:

             - reject connections seeking a different network
             - set connection state

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.chord.chord_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == flags.handshake:
            if packets[2] != self.protocol.id + to_base_58(self.k):
                self.disconnect(handler)
                return True
            if not handler.id:
                handler.id = packets[1]
                self._send_handshake(handler)
                handler.addr = json.loads(packets[3].decode())
                handler.compression = json.loads(packets[4].decode())
                handler.compression = [
                    algo.encode() for algo in handler.compression]
                self.__print__("Compression methods changed to %s"
                               % repr(handler.compression), level=4)
                self.set_fingers(handler)
                handler.send(flags.whisper, flags.peers,
                             json.dumps(self.__get_fingers()))
                if (distance(self.id_10, self.next.id_10-1, self.limit)
                        > distance(self.id_10, handler.id_10, self.limit)):
                    self.next = handler
                if (distance(self.prev.id_10+1, self.id_10, self.limit)
                        > distance(handler.id_10, self.id_10, self.limit)):
                    self.prev = handler
            return True

    def __handle_peers(self, msg, handler):
        """This callback is used to deal with peer signals. Its primary job
        is to connect to the given peers, if they are a better connection
        given the chord schema

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.chord.chord_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == flags.peers:
            new_peers = json.loads(packets[1].decode())
            for addr, key in new_peers:
                key = from_base_58(key)
                for index in xrange(self.k):
                    goal = self.id_10 + 2**index
                    self.__print__("%s : %s"
                                   % (distance(self.__findFinger__(goal).id_10,
                                               goal, self.limit),
                                      distance(key, goal, self.limit)),
                                   level=5)
                    if (distance(self.__findFinger__(goal).id_10, goal,
                                 self.limit)
                            > distance(key, goal, self.limit)):
                        self.__connect(*addr)
                if (distance(self.id_10, self.next.id_10-1, self.limit)
                        > distance(self.id_10, key, self.limit)):
                    self.__connect(*addr)
                if (distance(self.prev.id_10+1, self.id_10, self.limit)
                        > distance(key, self.id_10, self.limit)):
                    self.__connect(*addr)
            return True

    def __handle_response(self, msg, handler):
        """This callback is used to deal with response signals. Its two
        primary jobs are:

             - if it was your request, send the deferred message
             - if it was someone else's request, relay the information

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.chord.chord_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == flags.response:
            self.__print__(
                "Response received for request id %s" % packets[1], level=1)
            if self.requests.get((packets[1], packets[2])):
                value = self.requests.get((packets[1], packets[2]))
                value.value = packets[3]
                if value.callback:
                    value.callback_method(packets[1], packets[2])
            return True

    def __handle_request(self, msg, handler):
        """This callback is used to deal with request signals. Its three
         primary jobs are:

             - respond with a peers signal if packets[1] is ``'*'``
             - if you know the ID requested, respond to it
             - if you don't, make a request with your peers

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.chord.chord_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == flags.request:
            if packets[1] == b'*':
                handler.send(flags.whisper, flags.peers,
                             json.dumps(self.__get_fingers()))
            else:
                goal = from_base_58(packets[1])
                node = self.__findFinger__(goal)
                if node is not self:
                    node.send(flags.whisper, flags.request, packets[1], msg.id)
                    ret = awaiting_value()
                    ret.callback = handler
                    self.requests.update({(packets[1], msg.id): ret})
                else:
                    handler.send(flags.whisper, flags.response, packets[1],
                                 packets[2], self.out_addr)
            return True

    def __handle_retrieve(self, msg, handler):
        """This callback is used to deal with data retrieval signals. Its
        two primary jobs are:

             - respond with data you possess
             - if you don't possess it, make a request with your closest
             peer to that key

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.chord.chord_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == flags.retrieve:
            if packets[1] in hashes:
                val = self.__lookup(
                    packets[1], from_base_58(packets[2]), handler)
                if isinstance(val.value, str):
                    self.__print__(val.value)
                    handler.send(flags.whisper, flags.response, packets[1],
                                 packets[2], val.value)
                return True

    def __handle_store(self, msg, handler):
        """This callback is used to deal with data storage signals. Its two
        primary jobs are:

             - store data in keys you're responsible for
             - if you aren't responsible, make a request with your closest
             peer to that key

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.chord.chord_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == flags.store:
            method = packets[1]
            key = from_base_58(packets[2])
            self.__store(method, key, packets[3])
            return True

    def dump_data(self, start, end=None):
        """Args:
            start:  An :py:class:`int` which indicates the start of the
                        desired key range. ``0`` will get all data.
            end:    An :py:class:`int` which indicates the end of the
                        desired key range. ``None`` will get all data.
                        (default: ``None``)

        Returns:
            A nested :py:class:`dict` containing your data from start to end
        """
        i = start
        ret = dict(((method, {}) for method in hashes))
        for method in self.data:
            for key in self.data[method]:
                if (key >= start % self.limit and
                        (not end or key < end % self.limit)):
                    print(method, key, self.data)
                    ret[method].update({key: self.data[method][key]})
        return ret

    def connect(self, addr, port):
        """This function connects you to a specific node in the overall
        network. Connecting to one node *should* connect you to the rest of
        the network, however if you connect to the wrong subnet, the handshake
        failure involved is silent. You can check this by looking at the
        truthiness of this objects routing table. Example:

        .. code:: python

           >>> conn = chord.chord_socket('localhost', 4444)
           >>> conn.connect('localhost', 5555)
           >>> conn.join()
           >>> # do some other setup for your program
           >>> if not conn.routing_table:
           ...     conn.connect('localhost', 6666)  # any fallback address
           ...     conn.join()

        Args:
           addr: A string address
           port: A positive, integral port
           id:   A string-like object which represents the expected ID of
                     this node
        """
        self.__print__(
            "Attempting connection to %s:%s" % (addr, port), level=1)
        if (socket.getaddrinfo(addr, port)[0]
                == socket.getaddrinfo(*self.out_addr)[0]):
            self.__print__("Connection already established", level=1)
            return False
        conn = get_socket(self.protocol, False)
        conn.settimeout(1)
        conn.connect((addr, port))
        handler = chord_connection(conn, self, outgoing=True)
        self.awaiting_ids.append(handler)
        return handler

    def _send_handshake(self, handler):
        """Shortcut method for sending a handshake to a given handler

        Args:
            handler: A :py:class:`~py2p.chord.chord_connection`
        """
        json_out_addr = '["{}", {}]'.format(*self.out_addr)
        handler.send(flags.whisper, flags.handshake, self.id,
                     self.protocol.id + to_base_58(self.k),
                     json_out_addr, json_compressions)

    def __connect(self, addr, port):
        """Private API method for connecting and handshaking

        Args:
            addr: the address you want to connect to/handshake
            port: the port you want to connect to/handshake
        """
        try:
            handler = self.connect(addr, port)
            if handler and not self.leeching:
                self._send_handshake(handler)
        except:
            pass

    def join(self):
        """Tells the node to start seeding the chord table"""
        # for handler in self.awaiting_ids:
        self.leeching = False
        handler = random.choice(
            self.awaiting_ids or list(self.routing_table.values()))
        self._send_handshake(handler)

    def unjoin(self):
        """Tells the node to stop seeding the chord table, and dumps the
        data to the proper nodes
        """
        self.leeching = True
        temp_data = self.data
        self.data = dict(((method, dict()) for method in hashes))

        peers = self.awaiting_ids + list(self.routing_table.values())
        addrs = set([tuple(node.addr) for node in peers])

        for node in peers:
            self.disconnect(node)

        for addr in addrs:
            self.connect(*addr)

        for algo in temp_data:
            for key in temp_data[algo]:
                self.__store(algo, key, temp_data[algo][key])

    def __lookup(self, method, key, handler=None):
        if self.routing_table:
            node = self.__findFinger__(key)
        else:
            node = random.choice(self.awaiting_ids)
        if node in (self, None):
            return awaiting_value(self.data[method].get(key, ''))
        else:
            node.send(flags.whisper, flags.retrieve, method, to_base_58(key))
            ret = awaiting_value()
            if handler:
                ret.callback = handler
            self.requests.update({(method, to_base_58(key)): ret})
            return ret

    def lookup(self, key):
        """Looks up the value at a given key.

        Under the covers, this actually checks five different hash tables, and
        returns the most common value given.

        Args:
            key: The key that you wish to check. Must be a :py:class:`str` or
                    :py:class:`bytes`-like object

        Returns:
            The value at said key

        Raises:
            socket.timeout: If the request goes partly-unanswered for
                                >= 10 seconds
            KeyError:       If the request is made for a key with no
                                agreed-upon value
        """
        if not isinstance(key, (bytes, bytearray)):
            key = str(key).encode()
        keys = [int(hashlib.new(algo, key).hexdigest(), 16) for algo in hashes]
        vals = [self.__lookup(method, x) for method, x in zip(hashes, keys)]
        common, count = most_common(vals)
        iters = 0
        limit = 100
        while common == -1 and iters < limit:
            time.sleep(0.1)
            iters += 1
            common, count = most_common(vals)
        if common not in (None, '') and count > len(hashes) // 2:
            return common
        elif iters == limit:
            raise socket.timeout()
        raise KeyError("This key does not have an agreed-upon value", vals)

    def __getitem__(self, key):
        return self.lookup(key)

    def get(self, key):
        return self.__getitem__(key)

    def __store(self, method, key, value):
        node = self.__findFinger__(key)
        if self.leeching and node is self:
            node = random.choice(self.awaiting_ids)
        if node in (self, None):
            self.data[method].update({key: value})
        else:
            node.send(
                flags.whisper, flags.store, method, to_base_58(key), value)

    def store(self, key, value):
        """Updates the value at a given key.

        Under the covers, this actually uses five different hash tables, and
        updates the value in all of them.

        Args:
            key:    The key that you wish to update. Must be a
                        :py:class:`str` or :py:class:`bytes`-like object
            value:  The value you wish to put at this key. Must be a
                        :py:class:`str` or :py:class:`bytes`-like object
        """
        if not isinstance(key, (bytes, bytearray)):
            key = str(key).encode()
        keys = [int(hashlib.new(algo, key).hexdigest(), 16) for algo in hashes]
        for method, x in zip(hashes, keys):
            self.__store(method, x, value)

    def __setitem__(self, key, value):
        return self.store(key, value)

    def set(self, key, value):
        return self.__setitem__(key, value)

    def update(self, update_dict):
        """Equivalent to :py:meth:`dict.update`

        This calls :py:meth:`.chord_socket.store` for each key/value pair in
        the given dictionary.

        Args:
            update_dict: A :py:class:`dict`-like object to extract key/value
                            pairs from. Key and value be a :py:class:`str` or
                            :py:class:`bytes`-like object
        """
        for key in update_dict:
            value = update_dict[key]
            self.__setitem__(key, value)

    def disconnect(self, handler):
        """Closes a given connection, and removes it from your routing tables

        Args:
            handler: the connection you would like to close
        """
        node_id = handler.id
        if not node_id:
            node_id = repr(handler)
        self.__print__(
            "Connection to node %s has been closed" % node_id, level=1)
        if handler in self.awaiting_ids:
            self.awaiting_ids.remove(handler)
        elif handler in self.routing_table.values():
            for key in list(self.routing_table.keys()):
                if self.routing_table[key] is handler:
                    self.routing_table.pop(key)
        elif handler in self.predecessors:
            self.predecessors.remove(handler)
        try:
            handler.sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
