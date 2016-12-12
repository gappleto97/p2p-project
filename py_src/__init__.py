"""A collection of tools for peer-to-peer networking

In this module:

    Constants

      * __version__: A string containing the major, minor, and patch release
                        number
      * version_info: A tuple version of the above
      * protocol_version: A string containing the major and minor release
                            number. This refers to the underlying protocol.
      * node_policy_version: A string containing the build number associated
                                with this version. This refers to the node
                                and its policies.

    Classes

      * mesh_socket(addr, port, out_addr=None, debug_level=0,
                    prot=py2p.mesh.default_protocol):
          -  addr: The address you'd like to bind to
          -  port: The port you'd like to bind to
          -  out_addr: Your outward-facing address, if that is different
                        from (addr, port)
          -  prot: The py2p.base.protocol object you'd like to use
          -  debug_level: The verbosity at which this and its associated
             py2p.mesh.mesh_daemon prints debug information

Submodules:

    * base:        A library of common functions and classes to enable mesh
                    and the planned chord
    * mesh:        A library to deal with mesh networking
    * chord:       A planned library to deal with distributed hash tables
    * ssl_wrapper: A shortcut library to generate peer-to-peer ssl.SSLSockets
    * test:        Unit tests for this library
"""

from .base import Protocol, version
from .mesh import MeshSocket
# from .chord import chord_socket
# from .kademlia import kademlia_socket

# dht_socket = kademlia_socket

__version__ = version
version_info = tuple(map(int, __version__.split(".")))


def bootstrap(socket_type, proto, addr, port, *args, **kargs):
    raise NotImplementedError
    # global seed
    # seed = dht_socket(addr, port, out_addr = kargs.get('out_addr'))
    # seed.connect(standard_starting_conn)
    # time.sleep(1)
    # conn_list = json.loads(seed.get(proto.id))
    # ret = socket_type(addr, port, *args, prot=proto, **kargs)
    # for addr, port in conn_list:
    #     ret.connect(addr, port)
    # return ret

# __all__ = ["mesh", "chord", "kademlia", "base", "ssl_wrapper"]
__all__ = ["mesh", "base"]

try:
    import cbase
    __all__.append("cbase")
except ImportError:
    pass
