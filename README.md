# Version

This branch is an archive version for Yggdrasil v0.4.X compatibility. As of writing, ongoing developments happen in the `main` branch.

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

1. Packets are normally source routed.
2. If the sender has no source route to the destination, or a source routed packet reaches a dead end, then the packet falls back to routing through a distributed hash table.
3. Yggdrasil's routing scheme is used to find source routes and to set up routes between keyspace neighbors in the DHT. That means greedy routing in a metric space, where the metric space is defined by the distance between nodes in a spanning tree embedding of the network.

There are a ton of technical details about building the spanning tree, bootstrapping the DHT, responding to link failures, etc., all of which is beyond the scope of a readme file. All of those protocol level details are subject to change, so don't expect adequate documentation any earlier than the late alpha or early beta stage.

# Known Issues

Ironwood is an R&D project. As such, testing certain aspects of the routing scheme sometimes require making compromises in other areas, for the sake of development time. There would be no point in engineering a secure and efficient implementation of something that turns out not to solve the problem.

In particular, the current code implements a distributed data structure (for routing) with the goal of testing whether or not that data structure will work, if it scales, how efficient (low stretch) it is, how it responds to mobility, etc. While I am reasonably happy with the data structure, the algorithm to construct it has some known issues. The following is not meant to be an exhaustive list, bit it highlights most of the major ones:

1. Malicious nodes can drop traffic. Dropping traffic is necessary when dealing with congested links (the only alternative is to buffer an arbitrary amount of traffic, which would lead to out-of-memory attacks). This probably isn't fixable, just something to be aware of.

2. Malicious nodes can drop bootstrap packets that they should have acked. This allows the node to add itself to the DHT, but block anyone "after" them from joining the DHT.

3. Malicious nodes can tear down their own path after receiving a path. This involves doing things as normal up until they respond to a bootstrap (sending a bootstrap ack), waiting for the incoming setup, and then teardown down their own path. That disconnects the node *and anyone after them* from the rest of the DHT, which has mostly the same effect as the above, but it's much harder for victims to detect.

4. Malicious root nodes can anycast (use the same key on multiple nodes) to break the network. Specifically, this splits the DHT, and it *may* break treespace distance calculations in ways that prevent the DHT from bootstrapping at all.

5. Malicious nodes (other than the root) can anycast to break teh network. This also splits the DHT. It's noted separately because, while the effect is mostly the same, the mechanics of how it breaks the network (which protocol traffic is involved, etc) is different, so it's possible to fix one without fixing the other.

6. When a node drops offline, this temporarily introduces a hole into the DHT structure. Basically, if the DHT looks like A->B->C, and B goes offline, then there's a window of time where the A->B and B->C paths are both (in the process of being) removed, but where the A->C path to fix the problem has not (and cannot) be added to the network.

7. Somewhat related to the above, convergence time is asymptotically terrible. If we have two networks, and we link them together, it can take an excessively long time (at least O(n)) for the network to converge. This is because the two networks need to "zip" together one node at a time. For example, if we have A->C and B->D before the merge, then we need to build A->B before we know to remove A->C, and we need to do both those things before it's possible to build B->C (or even know that we need to build B->C), which must be built before we can remove B->D and add C->D. To be clear: requiring O(n) messages is *not* the problem, the problem is that we require O(n) *ordered* messages, which implies at least O(n) time (worse in practice, since there are multiple network hops during each step, which presumably scales with n).

8. Some essential protocol traffic requires round trips. That can be problematic when latency in the local network and latency of links in the global network differ significantly. In the extreme case, if we take the idea of a "world tree" literally, then a network with nodes on both earth and mars would be unusable *even within one planet* because of round trip protocol traffic that needs to go between planets. It's worth noting that the initial IP->key lookup and the crypto layer both require round trips, but that's a separate problem which is technically out of scope for the project (it's a research project on *routing*, not cryptography).

9. The current DHT is able to prevent traffic from unnecessarily leaving a subnet *if* there is exactly 1 gateway between the subnet and the rest of the network. Ideally, we would not want to exit a subnet just to re-enter via a different gateway. Going back to the mars example, even if the DHT was able to be constructed and kept consistent, having two gateways could case messages route from mars, to earth, and then back to mars. More realistically, if there's a local mesh network, we would like the network to be able to have multiple gateways to the internet overlay or bridges with other mesh networks, without those added links causing traffic within the local mesh to route outside and back in via a different gateway. This may turn out to be impossible (see e.g. Braess's paradox), but we can probably still do better than ignoring this completely.

10. Somewhat related to the above, there are some known network topologies where ironwood's stretch is terrible. Rings are the easiest example to point to: if two nodes are near each other, but on different side of the point that's directly opposite to the root, then their traffic will tend to take the long way (through the root) instead of going directly to each other. Ironwood also uses an unreasonable amount of memory on ring networks. We largely don't care about poor performance on rings, since they would lead to high path length even with a stretch-1 routing scheme. Unfortunately, ironwood performs poorly on spheres for largely the same, albeit with less memory use, which could become a major problem when building a large network *on earth*. There are ways to address this in the treespace routing scheme, but it's difficult to fix this in the DHT without introducing some security / denial-of-service vulnerabilities.
