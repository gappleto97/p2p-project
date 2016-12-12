from __future__ import print_function
from __future__ import absolute_import

import socket
import sys
import time

from .. import mesh
from ..base import Flags

if sys.version_info >= (3, ):
    xrange = range


def close_all_nodes(nodes):
    for node in nodes:
        node.close()


def propagation_validation(iters, start_port, num_nodes, encryption):
    for i in xrange(iters):
        print("----------------------Test start----------------------")
        nodes = [mesh.MeshSocket('localhost', start_port + i * num_nodes,
                                 prot=mesh.Protocol('', encryption), debug_level=5)]
        for j in xrange(1, num_nodes):
            new_node = mesh.MeshSocket('localhost', start_port + i * num_nodes + j,
                                       prot=mesh.Protocol('', encryption), debug_level=5)
            nodes[-1].connect('localhost', start_port + i*num_nodes + j)
            nodes.append(new_node)
            time.sleep(0.5)
        print("----------------------Test event----------------------")
        nodes[0].send(b"hello")
        time.sleep(num_nodes)
        print("----------------------Test ended----------------------")
        print(nodes[0].id)
        print([len(n.routing_table) for n in nodes])
        for node in nodes[1:]:
            print(node.status, len(node.routing_table))
            assert b"hello" == node.recv().packets[1]
            # Failure is either no message received: AttributeError
            #                   message doesn't match: AssertionError
        close_all_nodes(nodes)


def test_propagation_Plaintext(iters=3):
    propagation_validation(iters, 5100, 3, 'Plaintext')


def test_propagation_SSL(iters=3):
    propagation_validation(iters, 5200, 3, 'SSL')


def protocol_rejection_validation(iters, start_port, encryption):
    for i in xrange(iters):
        print("----------------------Test start----------------------")
        f = mesh.MeshSocket('localhost', start_port + i * 2,
                            prot=mesh.Protocol('test', encryption), debug_level=5)
        g = mesh.MeshSocket('localhost', start_port + i * 2 + 1,
                            prot=mesh.Protocol('test2', encryption), debug_level=5)
        print("----------------------Test event----------------------")
        g.connect('localhost', start_port + i*2)
        time.sleep(1)
        print("----------------------Test ended----------------------")
        assert len(f.routing_table) == len(f.awaiting_ids) == len(g.routing_table) == len(g.awaiting_ids) == 0
        close_all_nodes([f, g])


def test_protocol_rejection_Plaintext(iters=3):
    protocol_rejection_validation(iters, 5300, 'Plaintext')


def test_protocol_rejection_SSL(iters=3):
    protocol_rejection_validation(iters, 5400, 'SSL')


def register_1(msg, handler):
    packets = msg.packets
    if packets[1] == b'test':
        handler.send(Flags.whisper, Flags.whisper, b"success")
        return True


def register_2(msg, handler):
    packets = msg.packets
    if packets[1] == b'test':
        msg.reply(b"success")
        return True


def handler_registry_validation(iters, start_port, encryption, reg):
    for i in xrange(iters):
        print("----------------------Test start----------------------")
        f = mesh.MeshSocket('localhost', start_port + i * 2,
                            prot=mesh.Protocol('', encryption), debug_level=5)
        g = mesh.MeshSocket('localhost', start_port + i * 2 + 1,
                            prot=mesh.Protocol('', encryption), debug_level=5)

        f.register_handler(reg)
        g.connect('localhost', start_port + i*2)
        time.sleep(1)
        print("----------------------1st  event----------------------")
        g.send('test')
        time.sleep(1)
        print("----------------------1st  ended----------------------")
        assert all((not f.recv(), g.recv()))
        time.sleep(1)
        print("----------------------2nd  event----------------------")
        g.send('not test')
        time.sleep(1)
        print("----------------------2nd  ended----------------------")
        assert all((f.recv(), not g.recv()))
        close_all_nodes([f, g])


def test_hanlder_registry_Plaintext(iters=3):
    handler_registry_validation(iters, 5500, 'Plaintext', register_1)


def test_hanlder_registry_SSL(iters=3):
    handler_registry_validation(iters, 5600, 'SSL', register_1)


def test_reply_Plaintext(iters=3):
    handler_registry_validation(iters, 5700, 'Plaintext', register_2)


def test_reply_SSL(iters=3):
    handler_registry_validation(iters, 5800, 'SSL', register_2)


# def disconnect(node, method):
#     if method == 'crash':
#         connection = list(node.routing_table.values())[0]
#         connection.sock.shutdown(socket.SHUT_RDWR)
#     elif method == 'disconnect':
#         node.daemon.disconnect(list(node.routing_table.values())[0])
#     else:  # pragma: no cover
#         raise ValueError()


# def connection_recovery_validation(iters, start_port, encryption, method):
#     for i in xrange(iters):
#         print("----------------------Test start----------------------")
#         f = mesh.mesh_socket('localhost', start_port + i*3, prot=mesh.protocol('', encryption), debug_level=2)
#         g = mesh.mesh_socket('localhost', start_port + i*3 + 1, prot=mesh.protocol('', encryption), debug_level=2)
#         h = mesh.mesh_socket('localhost', start_port + i*3 + 2, prot=mesh.protocol('', encryption), debug_level=2)
#         f.connect('localhost', start_port + i*3 + 1)
#         g.connect('localhost', start_port + i*3 + 2)
#         time.sleep(0.5)
#         assert len(f.routing_table) == len(g.routing_table) == len(h.routing_table) == 2, "Initial connection failed"
#         print("----------------------Disconnect----------------------")
#         disconnect(f, method)
#         for j in range(4)[::-1]:
#             print(j)
#             time.sleep(1)
#         print("----------------------Test ended----------------------")
#         try:
#             assert len(f.routing_table) == len(g.routing_table) == len(h.routing_table) == 2, "Network recovery failed"
#         except:  # pragma: no cover
#             raise
#         finally:
#             print("f.status: %s\n" % repr(f.status))
#             print("g.status: %s\n" % repr(g.status))
#             print("h.status: %s\n" % repr(h.status))
#         close_all_nodes([f, g, h])


# def test_disconnect_recovery_Plaintext(iters=1):
#     connection_recovery_validation(iters, 5500, 'Plaintext', 'disconnect')


# def test_disconnect_recovery_SSL(iters=3):
#     connection_recovery_validation(iters, 5600, 'SSL', 'disconnect')


# def test_conn_error_recovery_Plaintext(iters=1):
#     connection_recovery_validation(iters, 5600, 'Plaintext', 'crash')


# def test_conn_error_recovery_SSL(iters=3):
#     connection_recovery_validation(iters, 5800, 'SSL', 'crash')
