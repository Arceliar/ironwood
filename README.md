# Ironwood

Ironwood is a routing library with a `net.PacketConn`-compatible interface using `ed25519.PublicKey`s as addresses. Basically, you use it when you want to communicate with some other nodes in a network, but you can't guarantee that you can directly connect to every node in that network. It was written to test improvements to / replace the routing logic in [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go), but it may be useful for other network applications.

Note: Ironwood is pre-alpha work-in-progress. There's no stable API, versioning, or expectation that any two commits will be compatible with each other. Also, it hasn't been audited by a security expert. While the author is unaware of any security vulnerabilities, it would be wise to think of this as an insecure proof-of-concept. Use it at your own risk.

## Packages

Ironwood is split into several sub-packages.

### Types

The `types` package exposes a `types.PacketConn` interface type. This is a superset of the `net.PacketConn` with a few extra functions to e.g. pass in `net.Conn` connections to peers. It uses the `types.Addr` as addresses, which is just a wrapper around `ed25519.PublicKey` implementing the `net.Addr` interface. You probably want to write your code in terms of these interface types, and then call `NewPacketConn` from one of the below packages, depending on what the requirements are for your application.

### Network

The `network` package implements all of the important routing logic. Packets sent over the `network.PacketConn` are unencrypted, unsigned, and otherwise at least as insecure as UDP. The main use case for this package is to wrap it with a more secure protocol (e.g. DTLS, QUIC, or TLS-over-μTP).

Internally, protocol traffic is signed (when necessary for authentication), but never encrypted, so this should be legal in environments where encryption is not permissible (e.g. amateur radio networks).

### Signed

The `signed` package is a small proof-of-concept wrapper around `network`. This package signs messages before sending and checks signatures upon receiving. This allows for some level of authentication without encryption, so it should still be legal for e.g. amateur radio networks.

### Encrypted

The `encrypted` package wraps `network` with ephemeral key [nacl/box]](https://pkg.go.dev/golang.org/x/crypto/nacl/box) (X25519/XSalsa20/Poly1305) for authenticated encryption, with ratcheting for improved forward secrecy and replay protection.

## Routing

The routing logic in `network` is still undocumented. The basic idea is:

1. Packets are normally forwarded using greedy routing in a metric space, where the metric space is defined by the distance between nodes in a spanning tree embedding of the network.
2. If the sender does not know the destination's location in treespace, or the routed packet reaches a dead end due to an incorrect (e.g. out-of-date) location, then the packet falls back to routing through a distributed hash table.

There are a ton of technical details about building the spanning tree, bootstrapping the DHT, responding to link failures, etc., all of which is beyond the scope of a readme file. All of those protocol level details are subject to change, so don't expect adequate documentation any earlier than the late alpha or early beta stage.

Note, however, that the "DHT" in the current release is just a full view of the spanning tree. This is done for debugging purposes, so we can focus on getting the underlying routing logic right before we try to build a typical `O(logn)` DHT on top of it. As such, the current version does not scale asymptotically better than other routing schemes (and incurs stretch that shortest path schemes do not experience), so this is not recommended for real-world use.

