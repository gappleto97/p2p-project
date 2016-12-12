from __future__ import print_function

import sys

from .base import (Protocol,
                   BaseConnection, BaseDaemon, BaseSocket)

default_protocol = Protocol('chord', "Plaintext")  # SSL")
hashes = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']

if sys.version_info >= (3,):
    xrange = range


def distance(a, b):
    raise NotImplementedError


class KademliaConnection(BaseConnection):
    pass


class KademliaDaemon(BaseDaemon):
    pass


class KademliaSocket(BaseSocket):
    pass