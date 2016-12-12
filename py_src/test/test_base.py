from __future__ import print_function
from __future__ import absolute_import

import hashlib
import os
import random
import struct
import sys
import uuid

import pytest

from functools import partial
from .. import base

if sys.version_info >= (3, ):
    xrange = range


def try_identity(in_func, out_func, data_gen, iters):
    for _ in xrange(iters):
        test = data_gen()
        assert test == out_func(in_func(test))


def gen_random_list(item_size, list_size):
    return [os.urandom(item_size) for _ in xrange(list_size)]


def test_base_58(iters=1000):
    max_val = 2**32 - 1
    data_gen = partial(random.randint, 0, max_val)
    try_identity(base.to_base_58, base.from_base_58, data_gen, iters)


def test_compression(iters=100):
    for method in base.compression:
        compress = partial(base.compress, method=method)
        decompress = partial(base.decompress, method=method)
        data_gen = partial(os.urandom, 36)
        try_identity(compress, decompress, data_gen, iters)


def test_compression_exceptions(iters=100):
    for _ in xrange(iters):
        test = os.urandom(36)
        with pytest.raises(Exception):
            base.compress(test, os.urandom(4))

        with pytest.raises(Exception):
            base.decompress(test, os.urandom(4))


def test_InternalMessage(iters=500, impl=base):
    max_val = 2**8
    for _ in xrange(iters):
        length = random.randint(0, max_val)
        array = gen_random_list(36, length)
        InternalMessage_constructor_validation(array, impl)
        InternalMessage_exceptions_validiation(array, impl)


def InternalMessage_constructor_validation(array, impl):
    msg = impl.InternalMessage(base.Flags.broadcast, u'\xff', array)
    assert array == msg.payload
    assert msg.packets == [base.Flags.broadcast, u'\xff'.encode('utf-8'), msg.id, msg.time_58] + array
    p_hash = hashlib.sha384(b''.join(array + [msg.time_58]))
    assert base.to_base_58(int(p_hash.hexdigest(), 16)) == msg.id
    assert impl.InternalMessage.feed_string(msg.string).id == msg.id
    if impl != base:
        assert base.InternalMessage.feed_string(msg.string).id == msg.id
    for method in impl.compression:
        msg.compression = []
        string = base.compress(msg.string[4:], method)
        string = struct.pack('!L', len(string)) + string
        msg.compression = [method]
        comp1 = impl.InternalMessage.feed_string(string, False, [method])
        comp2 = base.InternalMessage.feed_string(string, False, [method])
        assert msg.string == string == comp1.string == comp2.string


def InternalMessage_exceptions_validiation(array, impl):
    msg = impl.InternalMessage(base.Flags.broadcast, 'TEST SENDER', array)
    for method in impl.compression:
        msg.compression = [method]
        with pytest.raises(Exception):
            impl.InternalMessage.feed_string(msg.string, True, [method])

        with pytest.raises(Exception):
            impl.InternalMessage.feed_string(msg.string[4:], False, [method])

        with pytest.raises(Exception):
            impl.InternalMessage.feed_string(msg.string)


def test_protocol(iters=200, impl=base):
    for _ in range(iters):
        sub = str(uuid.uuid4())
        enc = str(uuid.uuid4())
        print("constructing")
        test = impl.Protocol(sub, enc)
        print("testing subnet equality")
        assert test.subnet == test[0] == sub
        print("testing encryption equality")
        assert test.encryption == test[1] == enc
        p_hash = hashlib.sha256(''.join([sub, enc, base.protocol_version]).encode())
        print("testing ID equality")
        assert base.to_base_58(int(p_hash.hexdigest(), 16)) == test.id


def test_message_sans_network(iters=1000):
    for _ in range(iters):
        sen = str(uuid.uuid4())
        pac = gen_random_list(36, 10)
        base_msg = base.InternalMessage(base.Flags.broadcast, sen, pac)
        test = base.Message(base_msg, None)
        assert test.packets == pac
        assert test.msg == base_msg
        assert test.sender == sen.encode()
        assert test.id == base_msg.id
        assert test.time == base_msg.time == base.from_base_58(test.time_58) == base.from_base_58(base_msg.time_58)
        assert sen in repr(test)
