import datetime, hashlib, os, random, struct, sys, time, uuid
from functools import partial
from .. import base

if sys.version_info[0] > 2:
    xrange = range

def try_identity(in_func, out_func, data_gen, iters):
    for i in xrange(iters):
        test = data_gen()
        assert test == out_func(in_func(test))

def gen_random_list(item_size, list_size):
    return [os.urandom(item_size) for i in xrange(list_size)]

def test_base_58(iters=1000):
    max_val = 2**32 - 1
    data_gen = partial(random.randint, 0, max_val)
    try_identity(base.to_base_58, base.from_base_58, data_gen, iters)

def test_intersect(iters=200):
    max_val = 2**12 - 1
    for i in xrange(iters):
        pair1 = sorted([random.randint(0, max_val), random.randint(0, max_val)])
        pair2 = sorted([random.randint(0, max_val), random.randint(0, max_val)])
        cross1 = [pair1[0], pair2[0]]
        cross2 = [pair1[1], pair2[1]]
        if max(cross1) < min(cross2):
            assert base.intersect(range(*pair1), range(*pair2)) == \
                                list(range(max(cross1), min(cross2)))
        else:
            assert base.intersect(range(*pair1), range(*pair2)) == []

def test_getUTC(iters=20):
    while iters:
        nowa, nowb = datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1), base.getUTC()
        assert nowa.days * 86400 + nowa.seconds in xrange(nowb-1, nowb+2)  # 1 second error margin
        time.sleep(random.random())
        iters -= 1

def test_lan_ip():
    if sys.platform[:5] == 'linux':
        lan_ip_validation_linux()
    elif sys.platform == 'darwin':
        lan_ip_validation_linux()
    elif sys.platform[:3] in ('win', 'cyg'):
        lan_ip_validation_windows()
    else:
        raise Exception("Unrecognized patform; don't know what command to test against")

def lan_ip_validation_linux():
    import subprocess
    # command pulled from http://stackoverflow.com/a/13322549
    command = """ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'"""
    if sys.version_info >= (2, 7):
        output = subprocess.check_output(command, universal_newlines=True, shell=True)
    else:  # fix taken from http://stackoverflow.com/a/4814985
        output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).communicate()[0]
    assert base.get_lan_ip() in output

def lan_ip_validation_windows():
    import subprocess
    # command pulled from http://stackoverflow.com/a/17634009
    command = """for /f "delims=[] tokens=2" %%a in ('ping %computername% -4 -n 1 ^| findstr "["') do (echo %%a)"""
    test_file = open('test.bat', 'w')
    test_file.write(command)
    test_file.close()
    if sys.version_info >= (2, 7):
        output = subprocess.check_output(['test.bat'])
    else:  # fix taken from http://stackoverflow.com/a/4814985
        output = subprocess.Popen(['test.bat'], stdout=subprocess.PIPE).communicate()[0]
    assert base.get_lan_ip().encode() in output
    os.remove('test.bat')

def test_compression(iters=100):
    for method in base.compression:
        compress = partial(base.compress, method=method)
        decompress = partial(base.decompress, method=method)
        data_gen = partial(os.urandom, 36)
        try_identity(compress, decompress, data_gen, iters)

def test_compression_exceptions(iters=100):
    for i in xrange(iters):
        test = os.urandom(36)
        try:
            base.compress(test, os.urandom(4))
        except:
            pass
        else:  # pragma: no cover
            raise Exception("Unknown compression method should raise error")
        try:
            base.decompress(test, os.urandom(4))
        except:
            pass
        else:  # pragma: no cover
            raise Exception("Unknown compression method should raise error")

def test_pathfinding_message(iters=500):
    max_val = 2**8
    for i in xrange(iters):
        length = random.randint(0, max_val)
        array = gen_random_list(36, length)
        pathfinding_message_constructor_validation(array)
        pathfinding_message_exceptions_validiation(array)

def pathfinding_message_constructor_validation(array):
    msg = base.pathfinding_message(base.default_protocol, base.flags.broadcast, 'TEST SENDER', array)
    assert array == msg.payload
    assert msg.packets == [base.flags.broadcast, 'TEST SENDER'.encode(), msg.id, msg.time_58] + array
    for method in base.compression:
        msg.compression = []
        string = base.compress(msg.string[4:], method)
        string = struct.pack('!L', len(string)) + string
        msg.compression = [method]
        comp = base.pathfinding_message.feed_string(base.default_protocol, string, False, [method])
        assert msg.string == string == comp.string

def pathfinding_message_exceptions_validiation(array):
    msg = base.pathfinding_message(base.default_protocol, base.flags.broadcast, 'TEST SENDER', array)
    for method in base.compression:
        msg.compression = [method]
        try:
            base.pathfinding_message.feed_string(base.default_protocol, msg.string, True, [method])
        except:
            pass
        else:  # pragma: no cover
            raise Exception("Erroneously parses sized message with sizeless: %s" % string)
        try:
            base.pathfinding_message.feed_string(base.default_protocol, msg.string[4:], False, [method])
        except:
            pass
        else:  # pragma: no cover
            raise Exception("Erroneously parses sizeless message with size %s" % string)
        try:
            base.pathfinding_message.feed_string(base.default_protocol, msg.string)
        except:
            pass
        else:  # pragma: no cover
            raise Exception("Erroneously parses compressed message as plaintext %s" % string)

def test_protocol(iters=200):
    for i in range(iters):
        sub = str(uuid.uuid4())
        enc = str(uuid.uuid4())
        test = base.protocol(sub, enc)
        assert test.subnet == test[0] == sub
        assert test.encryption == test[1] == enc
        p_hash = hashlib.sha256(''.join([sub, enc, base.version]).encode())
        assert int(p_hash.hexdigest(), 16) == base.from_base_58(test.id)

def test_message_sans_network(iters=1000):
    for i in range(iters):
        sub = str(uuid.uuid4())
        enc = str(uuid.uuid4())
        sen = str(uuid.uuid4())
        pac = gen_random_list(36, 10)
        prot = base.protocol(sub, enc)
        base_msg = base.pathfinding_message(prot, base.flags.broadcast, sen, pac)
        test = base.message(base_msg, None)
        assert test.packets == pac
        assert test.msg == base_msg
        assert test.sender == sen
        assert test.protocol == prot
        assert test.id == base_msg.id
        assert sen in repr(test)