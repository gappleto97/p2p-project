from __future__ import print_function, absolute_import

import json
import random
import select
import socket
import struct
import sys
import traceback

from collections import deque

try:
    from .cbase import protocol
except ImportError:
    from .base import Protocol

from .base import (Flags, compression, from_base_58,
                   BaseConnection, Message, BaseDaemon, BaseSocket,
                   json_compressions)
from .utils import getUTC, get_socket, intersect

max_outgoing = 4
default_protocol = protocol('mesh', "Plaintext")  # SSL")

class MeshConnection(BaseConnection):
    """The class for mesh connection abstraction. This inherits from :py:class:`py2p.base.base_connection`"""
    def send(self, msg_type, *args, **kargs):
        """Sends a message through its connection.

        Args:
            msg_type:   Message type, corresponds to the header in a :py:class:`py2p.base.InternalMessage` object
            *args:      A list of bytes-like objects, which correspond to the packets to send to you
            **kargs:    There are two available keywords:
            id:         The ID this message should appear to be sent from (default: your ID)
            time:       The time this message should appear to be sent from (default: now in UTC)

        Returns:
            the :py:class:`~py2p.base.InternalMessage` object you just sent, or None if the sending was unsuccessful
        """
        msg = super(MeshConnection, self).send(msg_type, *args, **kargs)
        if msg and (msg.id, msg.time) not in self.server.waterfalls:
            self.server.waterfalls.appendleft((msg.id, msg.time))

    def found_terminator(self):
        """This method is called when the expected amount of data is received

        Returns:
            ``None``
        """
        try:
            msg = super(MeshConnection, self).found_terminator()
        except (IndexError, struct.error):
            self.__print__("Failed to decode message. Expected first compression of: %s." % \
                            intersect(compression, self.compression), level=1)
            self.send(Flags.renegotiate, Flags.compression, json.dumps([]))
            self.send(Flags.renegotiate, Flags.resend)
            return
        packets = msg.packets
        self.__print__("Message received: %s" % packets, level=1)
        if self.handle_waterfall(msg, packets):
            return
        elif self.handle_renegotiate(packets):
            return
        self.server.handle_msg(Message(msg, self.server), self)

    def handle_waterfall(self, msg, packets):
        """This method determines whether this message has been previously received or not.

        If it has been previously received, this method returns ``True``.

        If it is older than a preset limit, this method returns ``True``.

        Otherwise this method returns ``None``, and forwards the message appropriately.

        Args:
            msg:        The message in question
            packets:    The message's packets

        Returns:
            Either ``True`` or ``None``
        """
        if packets[0] == Flags.broadcast:
            if from_base_58(packets[3]) < getUTC() - 60:
                self.__print__("Waterfall expired", level=2)
                return True
            elif not self.server.waterfall(Message(msg, self.server)):
                self.__print__("Waterfall already captured", level=2)
                return True
            self.__print__("New waterfall received. Proceeding as normal", level=2)


class MeshDaemon(BaseDaemon):
    """The class for mesh daemon. This inherits from :py:class:`py2p.base.base_daemon`"""
    def mainloop(self):
        """Daemon thread which handles all incoming data and connections"""
        while self.main_thread.is_alive() and self.alive:
            conns = list(self.server.routing_table.values()) + self.server.awaiting_ids
            for handler in select.select(conns + [self.sock], [], [], 0.01)[0]:
                if handler == self.sock:
                    self.handle_accept()
                else:
                    self.process_data(handler)
            for handler in conns:
                self.kill_old_nodes(handler)

    def handle_accept(self):
        """Handle an incoming connection"""
        if sys.version_info >= (3, 3):
            exceptions = (socket.error, ConnectionError)
        else:
            exceptions = (socket.error, )
        try:
            conn, addr = self.sock.accept()
            self.__print__('Incoming connection from %s' % repr(addr), level=1)
            handler = MeshConnection(conn, self.server)
            self.server._send_handshake(handler)
            handler.sock.settimeout(1)
            self.server.awaiting_ids.append(handler)
        except exceptions:
            pass

    def process_data(self, handler):
        """Collects incoming data from nodes"""
        try:
            while not handler.find_terminator():
                if not handler.collect_incoming_data(handler.sock.recv(1)):
                    self.__print__("disconnecting node %s while in loop" % handler.id, level=6)
                    self.server.disconnect(handler)
                    self.server.request_peers()
                    return
            handler.found_terminator()
        except socket.timeout:  # pragma: no cover
            return  # Shouldn't happen with select, but if it does...
        except Exception as e:
            if isinstance(e, socket.error) and e.args[0] in (9, 104, 10053, 10054, 10058):
                node_id = handler.id
                if not node_id:
                    node_id = repr(handler)
                self.__print__("Node %s has disconnected from the network" % node_id, level=1)
            else:
                self.__print__("There was an unhandled exception with peer id %s. This peer is being disconnected, and the relevant exception is added to the debug queue. If you'd like to report this, please post a copy of your mesh_socket.status to github.com/gappleto97/p2p-project/issues." % handler.id, level=0)
                self.exceptions.append((e, traceback.format_exc()))
            self.server.disconnect(handler)
            self.server.request_peers()


class MeshSocket(BaseSocket):
    """The class for mesh socket abstraction. This inherits from :py:class:`py2p.base.base_socket`"""
    def __init__(self, addr, port, prot=default_protocol, out_addr=None, debug_level=0):
        """Initializes a mesh socket

        Args:
            addr:           The address you wish to bind to (ie: "192.168.1.1")
            port:           The port you wish to bind to (ie: 44565)
            prot:           The protocol you wish to operate over, defined by a :py:class:`py2p.base.protocol` object
            out_addr:       Your outward facing address. Only needed if you're connecting
                over the internet. If you use '0.0.0.0' for the addr argument, this will
                automatically be set to your LAN address.
            debug_level:    The verbosity you want this socket to use when printing event data

        Raises:
            socket.error:   The address you wanted could not be bound, or is otherwise used
        """
        super(MeshSocket, self).__init__(addr, port, prot, out_addr, debug_level)
        self.requests = {}          # Metadata about message replies where you aren't connected to the sender
        self.waterfalls = deque()   # Metadata of messages to waterfall
        self.queue = deque()        # Queue of received messages. Access through recv()
        self.daemon = MeshDaemon(addr, port, self)
        self.register_handler(self.__handle_handshake)
        self.register_handler(self.__handle_peers)
        self.register_handler(self.__handle_response)
        self.register_handler(self.__handle_request)

    @property
    def outgoing(self):
        """IDs of outgoing connections"""
        return [handler.id for handler in self.routing_table.values() if handler.outgoing]

    @property
    def incoming(self):
        """IDs of incoming connections"""
        return [handler.id for handler in self.routing_table.values() if not handler.outgoing]

    def handle_msg(self, msg, conn):
        """Decides how to handle various message types, allowing some to be handled automatically"""
        if not super(MeshSocket, self).handle_msg(msg, conn):
            if msg.packets[0] in [Flags.whisper, Flags.broadcast]:
                self.queue.appendleft(msg)
            else:
                self.__print__("Ignoring message with invalid subflag", level=4)

    def __get_peer_list(self):
        """This function is used to generate a list-formatted group of your peers. It goes in format ``[ ((addr, port), ID), ...]``"""
        peer_list = [(self.routing_table[key].addr, key.decode()) for key in self.routing_table]
        random.shuffle(peer_list)
        return peer_list

    def _send_handshake(self, handler):
        """Shortcut method for sending a handshake to a given handler

        Args:
            handler: A :py:class:`~py2p.mesh.mesh_connection`
        """
        json_out_addr = '["{}", {}]'.format(*self.out_addr)
        handler.send(Flags.whisper, Flags.handshake, self.id, self.protocol.id, \
                     json_out_addr, json_compressions)

    def __resolve_connection_conflict(self, handler, h_id):
        """Sometimes in trying to recover a network a race condition is created.
        This function applies a heuristic to try and organize the fallout from
        that race condition. While it isn't perfect, it seems to have increased
        connection recovery rate from ~20% to ~75%. This statistic is from memory
        on past tests. Much improvement can be made here, but this statistic can
        likely never be brought to 100%.

        In the failure condition, the overall network is unaffacted *for large
        networks*. In small networks this failure condition causes a fork, usually
        where an individual node is kicked out.

        Args:
            handler: The handler with whom you have a connection conflict
            h_id:    The id of this handler
        """
        self.__print__("Resolving peer conflict on id %s" % repr(h_id), level=1)
        to_keep, to_kill = None, None
        if bool(from_base_58(self.id) > from_base_58(h_id)) ^ bool(handler.outgoing):  # logical xor
            self.__print__("Closing outgoing connection", level=1)
            to_keep, to_kill = self.routing_table[h_id], handler
            self.__print__(to_keep.outgoing, level=1)
        else:
            self.__print__("Closing incoming connection", level=1)
            to_keep, to_kill = handler, self.routing_table[h_id]
            self.__print__(not to_keep.outgoing, level=1)
        self.disconnect(to_kill)
        self.routing_table.update({h_id: to_keep})

    def _send_handshake_response(self, handler):
        """Shortcut method to send a handshake response. This method is extracted from :py:meth:`.__handle_handshake`
        in order to allow cleaner inheritence from :py:class:`py2p.sync.sync_socket`"""
        handler.send(Flags.whisper, Flags.peers, json.dumps(self.__get_peer_list()))

    def __handle_handshake(self, msg, handler):
        """This callback is used to deal with handshake signals. Its three primary jobs are:

             - reject connections seeking a different network
             - set connection state
             - deal with connection conflicts

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.mesh.mesh_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == Flags.handshake:
            if packets[2] != self.protocol.id:
                self.__print__("Connected to peer on wrong subnet. ID: %s" % packets[2], level=2)
                self.disconnect(handler)
                return True
            elif handler is not self.routing_table.get(packets[1], handler):
                self.__print__("Connection conflict detected. Trying to resolve", level=2)
                self.__resolve_connection_conflict(handler, packets[1])
            handler.id = packets[1]
            handler.addr = json.loads(packets[3].decode())
            handler.compression = json.loads(packets[4].decode())
            handler.compression = [algo.encode() for algo in handler.compression]
            self.__print__("Compression methods changed to %s" % repr(handler.compression), level=4)
            if handler in self.awaiting_ids:
                self.awaiting_ids.remove(handler)
            self.routing_table.update({packets[1]: handler})
            self._send_handshake_response(handler)
            return True

    def __handle_peers(self, msg, handler):
        """This callback is used to deal with peer signals. Its primary jobs is to connect to the given peers, if this does not exceed :py:const:`py2p.mesh.max_outgoing`

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.mesh.mesh_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == Flags.peers:
            new_peers = json.loads(packets[1].decode())
            for addr, id in new_peers:
                if len(self.outgoing) < max_outgoing:
                    try:
                        self.connect(addr[0], addr[1], id.encode())
                    except Exception:  # pragma: no cover
                        self.__print__("Could not connect to %s because\n%s" % (addr, traceback.format_exc()), level=1)
                        continue
            return True

    def __handle_response(self, msg, handler):
        """This callback is used to deal with response signals. Its two primary jobs are:

             - if it was your request, send the deferred message
             - if it was someone else's request, relay the information

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.mesh.mesh_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == Flags.response:
            self.__print__("Response received for request id %s" % packets[1], level=1)
            if self.requests.get(packets[1]):
                addr = json.loads(packets[2].decode())
                if addr:
                    msg = self.requests.get(packets[1])
                    self.requests.pop(packets[1])
                    self.connect(addr[0][0], addr[0][1], addr[1])
                    self.routing_table[addr[1]].send(*msg)
            return True

    def __handle_request(self, msg, handler):
        """This callback is used to deal with request signals. Its three primary jobs are:

             - respond with a peers signal if packets[1] is ``'*'``
             - if you know the ID requested, respond to it
             - if you don't, make a request with your peers

             Args:
                msg:        A :py:class:`~py2p.base.message`
                handler:    A :py:class:`~py2p.mesh.mesh_connection`

             Returns:
                Either ``True`` or ``None``
        """
        packets = msg.packets
        if packets[0] == Flags.request:
            if packets[1] == b'*':
                handler.send(Flags.whisper, Flags.peers, json.dumps(self.__get_peer_list()))
            elif self.routing_table.get(packets[2]):
                handler.send(Flags.broadcast, Flags.response, packets[1], json.dumps([self.routing_table.get(packets[2]).addr, packets[2].decode()]))
            return True

    def send(self, *args, **kargs):
        """This sends a message to all of your peers. If you use default values it will send it to everyone on the network

        Args:
            *args:      A list of strings or bytes-like objects you want your peers to receive
            **kargs:    There are two keywords available:
            flag:       A string or bytes-like object which defines your flag. In other words, this defines packet 0.
            type:       A string or bytes-like object which defines your message type. Changing this from default can have adverse effects.

        Warning:

            If you change the type attribute from default values, bad things could happen. It **MUST** be a value from :py:data:`py2p.base.flags` ,
            and more specifically, it **MUST** be either ``broadcast`` or ``whisper``. The only other valid flags are ``waterfall`` and ``renegotiate``,
            but these are **RESERVED** and must **NOT** be used.
        """
        send_type = kargs.pop('type', Flags.broadcast)
        main_flag = kargs.pop('flag', Flags.broadcast)
        # map(methodcaller('send', 'broadcast', 'broadcast', *args), self.routing_table.values())
        handlers = list(self.routing_table.values())
        for handler in handlers:
            handler.send(main_flag, send_type, *args)

    def __clean_waterfalls(self):
        """This function cleans the list of recently relayed messages based on the following heurisitics:

        * Delete all duplicates
        * Delete all older than 60 seconds
        """
        self.waterfalls = deque(set(self.waterfalls))
        self.waterfalls = deque((i for i in self.waterfalls if i[1] > getUTC() - 60))

    def waterfall(self, msg):
        """This function handles message relays. Its return value is based on
        whether it took an action or not.

        Args:
            msg: The :py:class:`~py2p.base.message` in question

        Returns:
            ``True`` if the message was then forwarded. ``False`` if not.
        """
        if msg.id not in (i for i, t in self.waterfalls):
            self.waterfalls.appendleft((msg.id, msg.time))
            for handler in self.routing_table.values():
                if handler.id != msg.sender:
                    handler.send_InternalMessage(msg.msg)
            self.__clean_waterfalls()
            return True
        else:
            self.__print__("Not rebroadcasting", level=3)
            return False

    def connect(self, addr, port, id=None):
        """This function connects you to a specific node in the overall network.
        Connecting to one node *should* connect you to the rest of the network,
        however if you connect to the wrong subnet, the handshake failure involved
        is silent. You can check this by looking at the truthiness of this objects
        routing table. Example:

        .. code:: python

           >>> conn = mesh.mesh_socket('localhost', 4444)
           >>> conn.connect('localhost', 5555)
           >>> # do some other setup for your program
           >>> if (!conn.routing_table):
           ...     conn.connect('localhost', 6666)  # any fallback address

        Args:
           addr: A string address
           port: A positive, integral port
           id:   A string-like object which represents the expected ID of this node
        """
        self.__print__("Attempting connection to %s:%s with id %s" % (addr, port, repr(id)), level=1)
        if socket.getaddrinfo(addr, port)[0] == socket.getaddrinfo(*self.out_addr)[0] or \
                                                            id in self.routing_table:
            self.__print__("Connection already established", level=1)
            return False
        conn = get_socket(self.protocol, False)
        conn.settimeout(1)
        conn.connect((addr, port))
        handler = MeshConnection(conn, self, outgoing=True)
        self._send_handshake(handler)
        if id:
            self.routing_table.update({id: handler})
        else:
            self.awaiting_ids.append(handler)

    def disconnect(self, handler):
        """Closes a given connection, and removes it from your routing tables

        Args:
            handler: the connection you would like to close
        """
        node_id = handler.id
        if not node_id:
            node_id = repr(handler)
        self.__print__("Connection to node %s has been closed" % node_id, level=1)
        if handler in self.awaiting_ids:
            self.awaiting_ids.remove(handler)
        elif self.routing_table.get(handler.id) is handler:
            self.routing_table.pop(handler.id)
        try:
            handler.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

    def request_peers(self):
        """Requests your peers' routing tables"""
        self.send('*', type=Flags.request, flag=Flags.whisper)

    def recv(self, quantity=1):
        """This function has two behaviors depending on whether quantity is truthy.

        If truthy is truthy, it will return a list of :py:class:`~py2p.base.message` objects up to length len.

        If truthy is not truthy, it will return either a single :py:class:`~py2p.base.message` object, or ``None``

        Args:
            quantity:   The maximum number of :py:class:`~py2p.base.message` s you would like to pull

        Returns:
            A list of :py:class:`~py2p.base.message` s, an empty list, a single :py:class:`~py2p.base.message` , or ``None``
        """
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
