"""A collection of tools for peer-to-peer networking

In this module:

  Guaranteed

    Constants

      * version: A string containing the major, minor, and patch release number. This version refers to the underlying protocol.
      * build_num: The build number associated with this version. This refers to the node and its policies.
      * __version__: A string containing both version and build_num separated by a "+". This is guarunteed to be unique.
      * version_info: A tuple version of the above
      * uses_RSA: This value says whether it is using the underlying rsa module. If None, it means neither rsa nor any of its fallbacks could be imported. Currently False means it relies on PyCrypto, and True means it relies on rsa.

    Classes

      * mesh_socket: 

  If rsa or Crypto is installed

    Constants

      * decryption_error: The error a call to decrypt will throw if decryption of a given ciphertext fails
      * verification_error: The error a call to verify will throw if verification of a given signature fails

    Methods

      * newkeys(keysize): Returns a tuple containing an RSA public and private key. The private key is guarunteed to work wherever a public key does. Format: (public_key, private_key)
      * encrypt(msg, key): Given a bytes plaintext and a public_key, returns an encrypted bytes
      * decrypt(msg, key): Given a bytes ciphertext and a private_key, either returns a decrypted `bytes` or throws `decryption_error`
      * sign(msg, key, hashop): Given a bytes, a private_key, and a hashop (["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]), returns a signed bytes
      * verify(msg, sig, key): Given a bytes message, a bytes signautre, and a public_key, either returns True or throws verification_error

    Classes

      * secure_socket

Submodules:
  
  Guaranteed
    * base:  A library of common functions and classes to enable mesh and the planned chord
    * mesh:  A library to deal with mesh networking
    * chord: A planned library to deal with distributed hash tables

  If rsa or Crypto is installed
    * net:   A library to make an RSA-encrypted sockets. Not present if rsa or Crypto is not installed
"""

from .mesh import mesh_socket
# from .chord import chord_socket
from .base import version, build_num

try:
    from .net import uses_RSA, decryption_error, verification_error, newkeys,\
                     encrypt, decrypt, sign, verify, secure_socket
except ImportError:  # pragma: no cover
    import warnings
    warnings.warn("Could not import encrypted socket module. Please install rsa from pip.", ImportWarning)
    uses_RSA = None

__version__ = version + "+" + build_num
version_info = tuple(map(int, version.split("."))) + (build_num.split('.')[0],) + tuple(map(int, build_num.split('.')[1:]))

__all__ = ["mesh", "chord", "base"]

if uses_RSA is not None:
    __all__.append("net")