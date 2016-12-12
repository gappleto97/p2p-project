from __future__ import print_function
from __future__ import absolute_import

try:
    import hashlib
    import os
    import random
    import struct
    import sys
    import uuid

    from functools import partial
    from .. import base, cbase

    from . import test_base

    if sys.version_info >= (3, ):
        xrange = range

    def test_flags():
        bf = base.Flags
        cf = cbase.flags
        assert bf.reserved == cf.reserved

        #main flags
        bf_main = (bf.broadcast, bf.whisper,
                   bf.renegotiate, bf.ping, bf.pong)
        cf_main = (cf.broadcast, cf.whisper,
                   cf.renegotiate, cf.ping, cf.pong)
        assert bf_main == cf_main

        #sub-flags
        bf_sub = (bf.broadcast, bf.compression, bf.whisper, bf.handshake,
                  bf.ping, bf.pong, bf.notify, bf.peers, bf.request,
                  bf.resend, bf.response, bf.store, bf.retrieve)
        cf_sub = (cf.broadcast, cf.compression, cf.whisper, cf.handshake,
                  cf.ping, cf.pong, cf.notify, cf.peers, cf.request,
                  cf.resend, cf.response, cf.store, cf.retrieve)
        assert bf_sub == cf_sub

        #common compression methods
        assert (bf.zlib, bf.gzip) == (cf.zlib, cf.gzip)

    def test_protocol():
        test_base.test_protocol(impl=cbase)

    def test_InternalMessage():
        test_base.test_InternalMessage(impl=cbase)

except ImportError:
    pass