# Ironwood

Ironwood is a routing library with a `net.PacketConn`-compatible interface using `ed25519.PublicKey`s as addresses. Basically, you use it when you want to communicate with some other nodes in a network, but you can't guarantee that you can directly connect to every node in that network. It was written to test improvements to / replace the routing logic in [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go), but it may be useful for other network applications.

Note: Ironwood is pre-alpha work-in-progress. There's no stable API, versioning, or expectation that any two commits will be compatible with each other. Also, it hasn't been audited by a security expert. While the author is unaware of any security vulnerabilities, it would be wise to think of this as an insecure proof-of-concept. Use it at your own risk.

## Packages

Ironwood is split into several sub-packages.

### Types

The `types` package exposes a `types.PacketConn` interface type. This is a superset of the `net.PacketConn` with a few extra functions to e.g. pass in `net.Conn` connections to peers. It uses the `types.Addr` as addresses, which is just a wrapper around `ed25519.PublicKey` implementing the `net.Addr` interface. You probably want to write your code in terms of these interface types, and then call `NetPacketConn` from one of the below packages, depending on what the requirements are for your application.

### Network

The `network` package implements all of the important routing logic. Packets sent over the `network.PacketConn` are unencrypted, unsigned, and otherwise at least as insecure as UDP. The main use case for this package is to wrap it with a more secure protocol (e.g. DTLS, QUIC, or TLS-over-μTP).

Internally, protocol traffic is signed (when necessary for authentication), but never encrypted, so this should be legal in environments where encryption is not permissible (e.g. amateur radio networks).

### Signed

The `signed` package is a small proof-of-concept wrapper around `network`. This package signs messages before sending and checks signatures upon receiving. This allows for some level of authentication without encryption, so it should still be legal for e.g. amateur radio networks.

### Encrypted

The `encrypted` package wraps `network` with ephemeral key [nacl/box]](https://pkg.go.dev/golang.org/x/crypto/nacl/box) (X25519/XSalsa20/Poly1305) for authenticated encryption, with ratcheting for improved forward secrecy and replay protection.

## Routing

The routing logic in `network` is still undocumented. The basic idea is:

1. Packets are normally source routed.
2. If the sender has no source route to the destination, or a source routed packet reaches a dead end, then the packet falls back to routing through a distributed hash table.
3. Yggdrasil's routing scheme is used to find source routes and to set up routes between keyspace neighbors in the DHT. That means greedy routing in a metric space, where the metric space is defined by the distance between nodes in a spanning tree embedding of the network.

There are a ton of technical details about building the spanning tree, bootstrapping the DHT, responding to link failures, etc., all of which is beyond the scope of a readme file. All of those protocol level details are subject to change, so don't expect adequate documentation any earlier than the late alpha or early beta stage.

# TODO

The following is a very rough TODO of what still needs to be implemented before this project is feature complete enough that it's worth calling it alpha / tagging whenever backwards compatibility breaks.

## Misc optimizations

There are lots of places in the code where we do something stupid but easy to write, instead of doing things the right way.
We should do things right. That usually means computing some things once, then holding on to the result (in read-only form, possibly distributing this to other actors) so we can reuse it without wasting resources.
E.g. pre-compute a DHT lookup table (use a radix trie or something) instead of looping over *everything* for every packet we're asked to forward.

## Wire formats

Currently the data structures that need to be sent over the wire are marshaled and unmarshaled by hand-written functions.
In the interest of clarity, it would *probably* make sense to just pick some well(-ish) known serialization format, and use that instead, even if it's slower.
There are a lot of options here, but all else being equal, clarity probably matters more than efficiency of the default implementation (since we could hand-write a parser to cover the special cases where we need to peek at something in-place for efficiency reasons).
All else being equal, it's probably preferable to use something well-known rather than something that wins in benchmarks, so protocol buffers are probably a good default option for lack of better ideas.
But it warrants further investigation.

## Expand DHT functionality

Currently the out-of-band code lets you notify the node that own an arbitrary key (and they can choose whether or not to respond, based on if/how they've set their handler).
To make it easier to implement a generic DHT, a node needs to be able to tell the PacketConn that it thinks it owns a key, and provide a handler for the PC to call if/when it no longer owns it (when we get a connection to a better owner).
This isn't high priority from a ygg-replacement standpoint (it's not needed for that use case), but it would be relatively easy to do and it could be generally nice to have.

## Protocol update(s)

1. Investigate keeping a second keyspace neighbor in each direction, so the chain isn't momentarily broken when a node joins. NOTE: Investigated, ultimately I think we'll need two neighbors per side + a different path setup order (path from next before path to prev), to prevent momentary disruption to the DHT when a node joins or leaves. Implementing/debugging/etc turns out to be more complicated than initially expected, so this is unlikely to happen until other things are in place and the existing code has been field tested.
2. ~The encrypted package could use some work... either switch to the noise protocol framework, or improve what's already there (to e.g. not send ephemeral pubkeys in plaintext).~
Done, traffic ephemeral keys are kept out of cleartext, among other improvements.

## DEBUG interface

~Some sort of debug interface is needed, to get read access to the low level internals. This (probably) doesn't need to be a stable API endpoint. It would be useful (in the ygg context) to e.g. check a node's coords, get a list of peers (with ports), dump out the full set of DHT info, etc.~
Done, but there's still some room for improvement.

