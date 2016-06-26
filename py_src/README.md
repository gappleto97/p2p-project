[Skip to file-wise API](#file-wise-api)

# Public API

## Constants

* `version`: A string containing the major, minor, and patch release number. This version refers to the underlying protocol.
* `build_num`: The build number associated with this version. This refers to the node and its policies.
* `__version__`: A string containing both `version` and `build_num` separated by a `"+"`. This is guarunteed to be unique.
* `uses_RSA`: This value says whether it is using the underlying `rsa` module. If `None`, it means neither `rsa` nor any of its fallbacks could be imported. Currently `False` means it relies on `PyCrypto`, and `True` means it relies on `rsa`.
* `if uses_RSA is not None`
    * `decryption_error`: The error a call to `decrypt` will throw if decryption of a given ciphertext fails
    * `verification_error`: The error a call to `verify` will throw if verification of a given signature fails

## Methods

* `if uses_RSA is not None`
    * `newkeys(keysize)`: Returns a tuple containing an RSA public and private key. The private key is guarunteed to work wherever a public key does. Format: `(public_key, private_key)`
    * `encrypt(msg, key)`: Given a `bytes` plaintext and a `public_key`, returns an encrypted `bytes`
    * `decrypt(msg, key)`: Given a `bytes` ciphertext and a `private_key`, either returns a decrypted `bytes` or throws `decryption_error`
    * `sign(msg, key, hashop)`: Given a `bytes`, a `private_key`, and a hashop (`["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]`), returns a signed `bytes`
    * `verify(msg, sig, key)`: Given a `bytes` message, a `bytes` signautre, and a `public_key`, either returns `True` or throws `verification_error`

## Classes

* [`mesh_socket`](#mesh_socket)
* `if uses_RSA is not None:` [`secure_socket`](#secure_socket)

# File-wise API

# base.py

This is used mostly for inheriting common functions with [`mesh.py`](#meshpy) and the planned [`chord.py`](#chordpy)

## Constants

* `version`: A string containing the major, minor, and patch release number. This version refers to the underlying protocol.
* `build_num`: The build number associated with this version. This refers to the node and its policies.
* `user_salt`: A `uuid4` which is generated uniquely in each running instance
* `compression`: A `list` of the compression methods your instance supports
* `default_protocol`: The default [`protocol`](#protocol) definition. This uses an empty string as the subnet and `PKCS1_v1.5` encryption, as supplied by [`net.py`](#netpy) (in alpha releases this will use `Plaintext`)
* `base_58`: The characterspace of base_58, ordered from least to greatest value

## Methods

* `to_base_58(i)`: Takes an `int` (or `long`) and returns its corresponding base_58 string (type: `bytes`)
* `from_base_58(string)`: Takes a base_58 string (or `bytes`) and returns its corresponding integer (type: `int`, `long`)
* `getUTC()`: Returns the current unix time in UTC (type: `int`)
* `compress(msg, method)`: Shortcut method for compression (type: `bytes`)
* `decompress(msg, method)`: Shortcut method for decompression (type: `bytes`)
* `get_lan_ip()`: Returns either your current local IP, or `"127.0.0.1"`

## Classes

### flags

This class is used as a namespace to store the various protocol defined flags.

* `broadcast`
* `bz2`
* `compression`
* `gzip`
* `handshake`
* `lzma`
* `peers`
* `waterfall`
* `resend`
* `response`
* `renegotiate`
* `request`
* `whisper`

### pathfinding_message

This class is used internally to deal with packet parsing from a socket level. If you find yourself calling this as a user, something's gone wrong.

#### Constructor

`pathfinding_message(protocol, msg_type, sender, payload, compressions=None)`
`pathfinding_message.feed_string(protocol, string, sizeless=False, compressions=None)`

* `protocol`: The [`protocol`](#protocol) this message uses
* `msg_type`: The chief [`flag`](#flag) this message uses, to broadcast intent
* `sender`: The SHA384-based sender ID
* `payload`: A `list` of additional packets to send
* `compressions`: A `list` of possible compression methods used/to use
* `string`: The raw message to parse
* `sizeless`: An indicator as to whether this message contains the length header

#### Constants

* `protocol`: The protocol this message is sent under
* `msg_type`: The main [flag](#flags) of the message (ie: `['broadcast', 'waterfall', 'whisper', 'renegotiate']`)
* `sender`: The sender id of this message
* `time`: An `int` of the message's timestamp
* `compression`: The `list` of compression methods this message may be under
* `compression_fail`: A debug property which is triggered if you give compression methods, but the message fed from `feed_string` is actually in plaintext

#### Properties

* `payload`: Returns the message's payload
* `compression_used`: Returns the compression method used
* `time_58`: Returns the timestamp in base_58
* `id`: Returns the message's id
* `len`: Returns the messages length header
* `packets`: Returns a `list` of the packets in this message, excluding the length header
* `string`: Returns a string version of the message, including the length header
* `__non_len_string`: Returns the string of this message without the size header

#### Methods

* `__len__()`: Returns the length of this message excluding the length header

#### Class Methods:

* `feed_string(ptorocol, string, sizeless=False, compressions=None)`: Given a [`protocol`](#protocol), a string or `bytes`, process this into a `pathfinding_message`. If compressions are enabled, you must provide a `list` of possible methods. If the size header is not included, you must specify this with `sizeless=True`. 
     Possible errors:

     * `AttributeError`: Fed a non-string, non-`bytes` argument
     * `AssertionError`: Initial size header is incorrect
     * `Exception`:      Unrecognized compression method fed in `compressions`
     * `struct.error`:   Packet headers are incorrect OR unrecognized compression
     * `IndexError`:     See `struct.error`

* `sanitize_string(string, sizeless=False)`: Given an `str` or `bytes`, returns a `bytes` object with no size header.
     Possible errors:

     * `AttributeError`: Fed a non-string, non-`bytes` argument
     * `AssertionError`: Initial size header is incorrect

* `decompress_string(string, compressions=None)`: Given a `bytes` object and list of possible compression methods, returns a decompressed version and a `bool` indicating if decompression failed. If decompression occurs, this will always return `bytes`. If not, it will return whatever you pass in. Decompression failure is defined as it being unable to decompress despite a list of possible methods being provided.
     Possible errors:

     * `Exception`:      Unrecognized compression method fed in `compressions`

* `process_string(string)`: Given a `bytes`, return a `list` of its contained packets.
     Possible errors:

     * `IndexError`:     Packet headers are incorrect OR not fed plaintext
     * `struct.error`:   See `IndexError` OR fed non-`bytes` object

### message

This class is returned to the user when a non-automated message is received. It contains sufficient information to parse a message or reply to it.

#### Constructor

`message(msg, server)`

* `msg`: This contains the [`pathfinding_message`](#pathfinding_message) you received
* `server`: The [`base_socket`](#base_socket) which received the message

#### Constants

* `msg`: This contains the [`pathfinding_message`](#pathfinding_message) you received
* `server`: The [`base_socket`](#base_socket) which received the message

#### Properties

* `time`: The UTC Unix time at which the message was sent
* `sender`: The original sender's ID
* `protocol`: The [`protocol`](#protocol) you received this under
* `packets`: Returns a `list` of the packets received, with the first item being the subflag
* `id`: Returns the SHA384-based message id

#### Methods

* `reply(*args)`: Sends a [`whisper`](#flags) to the original sender with the arguments being each packet after that. If you are not connected, it uses the [`request`/`response`](#flags) mechanism to try making a connection

### protocol

This class inherits most of its methods from a `namedtuple`. This means that each of the properties in the constructor can be accessed by name or index. Mostly you'll be doing this by name.

#### Constructor

`protocol(subnet, encryption)`

#### Constants

* `subnet`: A flag to allow people with the same package version to operate different networks
* `encryption`: Defines the encryption standard used on the socket

#### Properties

* `id`: Returns the SHA256-based protocol id

### base_socket

#### Variables

* `debug_level`: The verbosity of the socket with debug prints
* `routing_table`: The current `dict` of peers in format `{id: connection}`
* `awaiting_ids`: A `list` of connections awaiting a handshake
* `queue`: A `deque` of recently received [`message`](#message)s
* `daemon`: This node's [`base_daemon`](#base_daemon) object

#### Properties

* `outgoing`: A `list` of ids for outgoing connections
* `incoming`: A `list` of ids for incoming connections
* `status`: Returns `"Nominal"` or `base_socket.daemon.exceptions` if there are `Exceptions` collected

#### Methods:

* `recv(quantity=1)`: Receive [`message`](#message)s; If `quantity != 1`, returns a `list` of [`message`](#message)s, otherwise returns one
* `__print__(*args, level=None)`: Prints debug information if `level >= debug_level`

### base_daemon

#### Constructor

`base_daemon(addr, port, server, prot=default_protocol)`

* `addr`: The address it should bind its incoming connection to
* `port`: The port it should bind its incoming connection to
* `server`: This daemon's [`base_socket`](#base_socket)
* `prot`: This daemon's [`protocol`](#protocol)

#### Variables

* `protocol`: This daemon's [`protocol`](#protocol) object
* `server`: A pointer to this daemon's [`base_socket`](#base_socket)
* `sock`: This daemon's `socket` object
* `alive`: A checker to shutdown the daemon. If `False`, its thread will stop running eventually.
* `exceptions`: A `list` of unhandled `Exception`s raised in `mainloop`
* `daemon`: A `Thread` which runs through `mainloop`

#### Methods

* `__print__(*args, level=None)`: Prints debug information if `level >= server.debug_level`

### base_connection

#### Constructor

`base_connection(sock, server, prot=default_protocol, outgoing=False)`

* `sock`: A `socket.socket`
* `server`: This node's [`base_socket`](#base_socket)
* `prot`: This node's [`protocol`](#protocol)
* `outgoing`: Whether or not this node is an outgoing connection

#### Variables:

* `sock`: This connection's `socket` object
* `server`: A pointer to this connection's [`base_socket`](#base_socket) object
* `protocol`: This connection's [`protocol`](#protocol) object
* `outgoing`: A `bool` that states whether this connection is outgoing
* `buffer`: A `list` of recently received characters
* `id`: This node's SHA384-based id
* `time`: The time at which this node last received data
* `addr`: This node's outward-facing address
* `compression`: A `list` of this node's supported compression methods
* `last_sent`: A copy of the most recently sent `whisper` or `broadcast`
* `expected`: The number of bytes expected in the next message
* `active`: A `bool` which says whether the next message is a size header, or a message (`True` if message)

#### Methods

* `fileno()`: Returns `sock`'s file number
* `collect_incoming_data(data)`: Adds new data to the buffer
* `find_terminator()`: Determines if a message has been fully received (name is a relic of when this had an `end_of_tx` flag)
* `__print__(*args, level=None)`: Prints debug information if `level >= server.debug_level`

# mesh.py

Note: This inherits a *lot* from [`base.py`](#basepy), and imported values will *not* be listed here, for brevity's sake.

## Constants

* `compression`: A `list` of the compression methods your instance supports
* `max_outgoing`: The (rough) maximum number of outgoing connections your node will maintain
* `default_protocol`: The default [`protocol`](#protocol) definition. This uses `'mesh'` as the subnet and `PKCS1_v1.5` encryption, as supplied by [`net.py`](#netpy) (in alpha releases this will use `Plaintext`)

## Classes

### mesh_socket

This peer-to-peer socket is the main purpose behind this library. It maintains a connection to a mesh network. Details on how it works specifically are outlined [here](../README.md), but the basics are outlined below.

It also inherits all the attributes of [`base_socket`](#base_socket), though they are also outlined here

#### Constructor

`mesh_socket(addr, port, prot=default_protocol, out_addr=None, debug_level=0)`

* `addr`: The address you'd like to bind to
* `port`: The port you'd like to bind to
* `prot`: The [`protocol`](#protocol) you'd like to use
* `out_addr`: Your outward-facing address, if that is different from `(addr, port)`
* `debug_level`: The verbosity at which this and its associated [`mesh_daemon`](#mesh_daemon) prints debug information

#### Variables

* `protocol`: A [`protocol`](#protocol) object which contains the subnet flag and the encryption method
* `debug_level`: The verbosity of the socket with debug prints
* `routing_table`: The current `dict` of peers in format `{id: connection}`
* `awaiting_ids`: A `list` of connections awaiting a handshake
* `outgoing`: A `list` of ids for outgoing connections
* `incoming`: A `list` of ids for incoming connections
* `requests`: A `dict` of the requests this node has made in format `{request_id: delayed_message_contents}`
* `waterfalls`: A `deque` of metadata for recently received [`message`](#message)s
* `queue`: A `deque` of recently received [`message`](#message)s
* `out_addr`: A `tuple` which contains the outward facing address and port
* `id`: This node's SHA384-based id
* `daemon`: This node's [`mesh_daemon`](#mesh_daemon) object

#### Methods

* `connect(addr, port, id=None)`: Connect to another `mesh_socket` (and assigns id if specified)
* `send(*args, type='broadcast')`: Send a message to your peers with each argument as a packet
* `recv(quantity=1)`: Receive [`message`](#message)s; If `quantity != 1`, returns a `list` of [`message`](#message)s, otherwise returns one
* `handle_request(msg)`: Allows the daemon to parse subflag-level actions
* `waterfall(msg)`: Waterfalls a [`message`](#message) to your peers

### mesh_daemon

This inherits all the attributes of [`base_daemon`](#base_daemon), though they are also outlined here

#### Constructor

`mesh_daemon(addr, port, server, prot=default_protocol)`

* `addr`: The address it should bind its incoming connection to
* `port`: The port it should bind its incoming connection to
* `server`: This daemon's [`mesh_socket`](#mesh_socket)
* `prot`: This daemon's [`protocol`](#protocol)

#### Variables

* `protocol`: This daemon's [`protocol`](#protocol) object
* `server`: A pointer to this daemon's [`mesh_socket`](#mesh_socket)
* `sock`: This daemon's `socket` object
* `alive`: A checker to shutdown the daemon. If `False`, its thread will stop running eventually.
* `exceptions`: A `list` of unhandled `Exception`s raised in `mainloop`
* `daemon`: A `Thread` which runs through `mainloop`

#### Methods

* `mainloop()`: The method through which `daemon` parses. This runs as long as `alive` is `True`, and alternately calls the `collect_incoming_data` methods of [`mesh_connection`](#mesh_connection)s and `handle_accept`.
* `handle_accept()`: Deals with incoming connections
* `disconnect(handler)`: Closes a given [`mesh_connection`](#mesh_connection) and removes its information from `server`
* `__print__(*args, level=None)`: Prints debug information if `level >= server.debug_level`

### mesh_connection

This inherits all the attributes of [`base_connection`](#base_connection), though they are also outlined here

#### Constructor

`base_connection(sock, server, prot=default_protocol, outgoing=False)`

* `sock`: A `socket.socket`
* `server`: This node's [`mesh_socket`](#mesh_socket)
* `prot`: This node's [`protocol`](#protocol)
* `outgoing`: Whether or not this node is an outgoing connection

#### Variables:

* `sock`: This connection's `socket` object
* `server`: A pointer to this connection's [`mesh_socket`](#mesh_socket) object
* `protocol`: This connection's [`protocol`](#protocol) object
* `outgoing`: A `bool` that states whether this connection is outgoing
* `buffer`: A `list` of recently received characters
* `id`: This node's SHA384-based id
* `time`: The time at which this node last received data
* `addr`: This node's outward-facing address
* `compression`: A `list` of this node's supported compression methods
* `last_sent`: A copy of the most recently sent [`whisper`](#flags) or [`broadcast`](#flags)
* `expected`: The number of bytes expected in the next message
* `active`: A `bool` which says whether the next message is a size header, or a message (`True` if message)

#### Methods

* `fileno()`: Returns `sock`'s file number
* `collect_incoming_data(data)`: Adds new data to the buffer
* `find_terminator()`: Determines if a message has been fully received (name is a relic of when this had an `end_of_tx` flag)
* `found_terminator()`: Deals with any data received when `find_terminator` returns `True`
* `send(msg_type, *args, id=server.id, time=base.getUTC())`: Sends a message via `sock`
* `__print__(*args, level=None)`: Prints debug information if `level >= server.debug_level`

# net.py

## Constants

* `uses_RSA`: Defines whether you're using the `rsa` module
* `decryption_error`: The `Exception` this module catches when decryption fails
* `verification_error`: The `Exception` this module catches when signature verification fails
* `key_request`: The message used to request a peer's key
* `size_request`: The message used to request a peer's keysize

## Methods

* `newkeys(keysize)`: Returns a tuple containing an RSA public and private key. The private key is guarunteed to work wherever a public key does. Format: `(public_key, private_key)`
* `encrypt(msg, key)`: Given a `bytes` plaintext and a `public_key`, returns an encrypted `bytes`
* `decrypt(msg, key)`: Given a `bytes` ciphertext and a `private_key`, either returns a decrypted `bytes` or throws `decryption_error`
* `sign(msg, key, hashop)`: Given a `bytes`, a `private_key`, and a hashop (`["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]`), returns a signed `bytes`
* `verify(msg, sig, key)`: Given a `bytes` message, a `bytes` signautre, and a `public_key`, either returns `True` or throws `verification_error`
* `public_key(n, e)`: Returns a public key object

## Classes

### secure_socket

This is a socket through which all information is encrypted with RSA. It behaves like a `socket.socket`, with a few caveats.

1. There is a character limit on a single send call. Mind you, this is ~133 GiB at its most restrictive, but it exists.
2. You don't need to specify how many bytes to read. If you don't, it will return a single message. If you do, it will return up to that size, but (like a `socket.socket`) is not guarunteed to. It keeps an internal buffer, and if you request more than this buffer, it will only return up to that buffer. It will not look for more information. This latter part is a possible improvement to make.
3. If there is data in its internal buffer, and no data is set to be received, `select.select` will not report it as available to read.

#### Constructor

`secure_socket(sock_family=socket.AF_INET, sock_type=socket.SOCK_STREAM, proto=0, fileno=None, keysize=1024, silent=False)`

* `sock_family`: Equivalent to the `family` argument on a `socket.socket`
* `sock_type`: Equivalent to the `type` argument on a `socket.socket`
* `proto`: Equivalent to the `proto` argument on a `socket.socket`
* `fileno`: Equivalent to the `fileno` argument on a python3 `socket.socket`, or the `_sock` argument on a python2 `socket.socket`
* `keysize`: The RSA keysize you wish to generate. If `PyCrypto` is the underlying library, it will only accept it if `keysize % 256 != 0 and keysize >= 1024`. The object itself will reject any value not in `range(354, 8197)`. Higher than this will raise a warning, lower a `ValueError`
* `silent`: This will suppress the prints from handshaking

#### Variables

* `family`: Inherited from `socket.socket`
* `type`: Inherited from `socket.socket`
* `proto`: Inherited from `socket.socket`
* `keysize`: The keysize you specified while constructing
* `pub`: Your public key
* `priv`: Your private key
* `recv_charlimit`: The maximum number of characters you can receive in a single message (guarunteed >85899345640)
* `peer_keysize`: Your peer's keysize (or `None` if you are not connected)
* `key`: Your peer's key (or `None` if you are not connected)
* `send_charlimit`: The maximum number of characters you can send in a single message (guarunteed >85899345640, or `None` if not connected)

#### Methods

* `connect(ip)`: Attempts to connect to the given address
* `bind(ip)`: Binds to the given ip address (inherited from `socket.socket`)
* `listen(i)`: Allow the given number of incoming connections to queue
* `accept()`: Returns a connection and address
* `close()`: Closes the connection
* `dup()`: Returns a copy of the `socket`
* `settimeout(i)`: Sets the `socket` timeout; blocks if a handshake is occurring
* `send(msg)`: Sends an encrypted message, with an encrypted signature; blocks if a handshake is occurring
* `recv(size=None)`: Receives a message. If a size is given, returns that number of characters. Blocks if no message is available, or `raise`s `socket.timeout` if not received within the assigned timeout; blocks completely if a handshake is occurring
* `sign(msg, hashop='best')`: Returns a signature of the given text; If you define a hashop, it will use that. Otherwise it uses the largest available. Valid ops are `['SHA-512', 'SHA-384', 'SHA-256', 'SHA-1', 'MD5']`
* `verify(msg, sig, key=None)`: Returns whether the signature is valid. If a key is not specified, defaults to its own key