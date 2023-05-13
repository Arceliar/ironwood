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
2. If a packet becomes unroutable (e.g. reaches a dead end), then a path broken notification is sent to the sender (via treespace).
3. If the sender does not know the destination's location in treespace, or receives a path broken notification, the sender does a lookup of the node's destination.

There are a ton of technical details about building the spanning tree, bootstrapping, responding to link failures, etc., all of which is beyond the scope of a readme file. All of those protocol level details are subject to change, so don't expect adequate documentation any earlier than the late alpha or early beta stage.

### Spanning Tree

The spanning tree is made up of a constant size message per node specifying which peer of that node acts as its parent (or itself, in the case of the root). These are stored in a soft-state CRDT-Set, and some subset of the information is gossiped with each peer (specifically, the spanning tree ancestry of the sending node and the peer). CRDT semantics ensures that two peered node's views of their shared relevant part of the tree are eventually consistent, and that updates to a common ancestor of multiple peers are applied atomically to all peer records stored in the local routing table.

### Lookups

The key->location lookup protocol resembles ARP from IPv4 or NDP from IPv6 when these are run on an ethernet network. The protocol uses multicast traffic sent over the spanning tree. Each node connected to an on-tree link maintains a bloom filter of which nodes are reachable by routing a message towards that part of the tree. This allows lookups to be routed with only constant state per peer needed at each node. The tradeoff is that there is a non-zero false positive rate: nodes may *appear* to lead to a subtree that contains the destination key, but in fact contain one or more unrelated addresses that set the same bits of the bloom filter, and so the node may end up routing lookup traffic unnecessarily (until it becomes apparent that there is no path to a node with a key that passes the filter). As these lookups are routed as multicast traffic, this does not prevent the intended destination from receiving the lookup traffic, it just causes unnecessary copies of the traffic to be gossiped around some portion of the network.

To put precise numbers on this: an 8192-bit bloom filter is used (1024 bytes, small enough to fit into a single minimum unfragmented size 1280-byte IPv6 packet when typical TCP/IP headers are included). The bloom filters use 8 hash functions per key. For a bloom filter that contains a single key (e.g. a leaf node), this results in a false positive rate approximately the same as an 80-bit address collision. For a 1 million node network, the first false positive is expected when a bloom filter contains about 200 nodes (i.e. if you are a gateway to a subtree with 200 nodes, then in a 1 million node network, you can expect 1 node outside of your subtree to match your bloom filter and cause lookups for it to be routed to your gateway node). In the same network, a majority of nodes that pass your bloom filter are expected to be true positives up to subtrees of about 500 nodes.

As full knowledge of the destination key may not be available (e.g. in Yggdrasil, we can only rely on knowing at least the bits of the key that fit into a `/64` prefix address), applications configure a transformation to be applied to keys before adding to or querying the bloom filters. Given the ~80-bit collision resistance of leaf node bloom filters, a subnet address collision in Yggdrasil is more likely than a leaf node bloom filter collision until about 32 extra bits of key have been brute forced into the subnet address. In other words: it is statistically implausible that leaf nodes will see *any* unnecessary lookup traffic due to false positives in the lookup structure.

This lookup protocol is meant to replace the necessary functionality provided by the DHT routing and pathfinder logic in earlier version of Ironwood (used in Yggdrasil v0.4.X). A change of some kind was needed for a few reasons:

1. The DHT used in Ygg v0.4.X is a hard state routing protocol. This is hard to secure, and can require fairly high memory use per node for some nodes, but the bandwidth use is low (both idle and to route enough traffic to perform pathfinding).
2. The soft state DHT variant (never used in Ygg, similar to what was later adopted by Matrix's pinecone) is more secure against attacks, but it requires relatively frequent keep-alive traffic to prevent the soft state from expiring.
3. Either version of the DHT has a worst case `O(n)` convergence time, ignoring the time needed to route messages between keyspace neighbors. In particular, if two networks are joined, they need to "zip together" 1 node at a time.

The new lookup protocol is expected to be at least as secure as the soft state DHT, use (asymptotically) as little bandwidth as the hard state DHT, and converge as fast as the spanning tree itself, while requiring only constant state per peer. The down side is the possibility for higher lookup cost compared to the old DHT-based protocol, for some "core" region of the network, due to the significant false positive rate. Given that nodes in the core of the network are expected to need high bandwidth anyway (to carry user application traffic), this seems like it could be a preferable direction to explore in the tradeoff space.

