# Ironwood

A project description will come later. Ironwood is pre-alpha work-in-progress and is not expected to be fit for purpose for any use case.

## TODO

The following is a very rough TODO of what still needs to be implemented before this project is feature complete enough that it's worth testing (as are replacement to ygg's core or as a stand-alone network or something).

### Tree

The current tree structure is a completely hard state protocol with no sequence number from the root. It would be better to make the tree updates more ygg-like, where the root periodically updates a sequence number and sends a new announcement, and nodes time out the old root if it they don't see a new (higher) sequence number after some amount of time. Within the life of one sequence numbered announcement, the current hard-state protocol would be kept. This would mainly be as protection against malicious nodes (refusing to remove an old root path after it their parent goes offline), and to protect against hard-state errors from e.g. cosmic ray bit flips or other impossible to predict hardware problems. Parent selection could also be based (initially) on minimum latency to the root / maximum reliability (basically, you use the newest timestamp that has advertised the same path for the longest period of time). So the tree would basically work like B.A.T.M.A.N.

Also, maybe we should allow multiple connections to/from the same node (currently it's fixed at 1, since we identify peers by key instead of anything like a ygg port number, so that probably needs changing).

### DHT

Currently, a node tears down its successor and predecessor paths if its parent changes. Instead, we should use the root announcement sequence number to move things forward without breaking paths completely. When a new sequence number (or better root) is seen, nodes would open a new path to a successor/predecessor (basically, keep forwarding traffic using old paths if there's no alternative, but don't consider the old paths when deciding if a new successor/predecessor is OK). Nodes would tear down the old paths (starting at the predecessor side) when the new path is ready. This would prevent transient DHT holes from appearing in cases where coords update but he old DHT paths would still work.

Additionally, we should probably store the second to best successor/predecessor, if it's safe to do so without opening up new (memory-exhaustion) DoS attacks on the network. In particular, if the 2nd best successor slot is open, then ask our successor for info about its own successor (requires new protocol traffic). We would then open a path to the 2nd successor, and accept a path from the second predecessor. We'd need to be careful about how we detect when we should replace one of these nodes -- we don't want to think that a node is our predecessor when they should really be our 2nd predecessor for example. The goal here is to make it so removing any 1 node doesn't open up any holes in the DHT (if our predecessor disappears, we already know a 2nd predecessor that we can fall back on, if we can figure out the upgrade step without breaking anything).

### Source routing

The first (few) packet(s) are expected to be routed via the DHT, but then we should switch to source routing that uses ygg's algorithm for path discovery. Each node would keep a cache that maps keys onto a source route. When trying to send to a given key, we'd encapsulate the DHT packet into a source routed packet. If the source routed packet hits a dead-end (other than the destination node), then it could (possibly) send back an error message (to immediately remove the source route from the node's cache), and then the dead-end node would pull the DHT packet out of the source packet and forward it the rest of the way via DHT.

The trick is figuring out when and how we discover a source route. Either the sender or the receiver needs to initiate source route discovery. Implementation details aside, I can think of basically 4 strategies we could use here, each with their own pros and cons:

1. The sender sends their coords to the destination via the DHT in a new protocol packet, and the destination replies by sending a packet back to those coords. The path back to the destination is appended (in ygg-like port number format) at each hop along the way. The sender's path is then the reverse of the `dest->source` path. This involves a 2-way trip.
2. The sender sends a coord request packet to the destination, and the destination replies with its coords (all via the DHT). The sender then sends a ping that's routed ygg-like to the destination, with the reverse path saved along the way, and the destination acks along the reverse path. The reverse of the reverse path is what the sender receives, so they'd end up with the `S->D` path. This involves a 4-way trip.
3. The destination initiates the lookup after receiving a DHT-routed packet addressed to their own key (not a DHT dead-end packet from e.g. a partial key match). In this scenario, every DHT-routed packet has the source coords included in it, so the dest just sends a ygg-routed reply. The source ends up with the `D->S` path. This is basically case 1, except it piggybacks on top of all DHT traffic. This involves a 1-way trip (if we count the initial DHT-routed packet as happening "for free").
4. Analogous to case 2 in the same way that case 3 is analogous to case 1. When the dest receives a DHT-routed packet, it sends an ack (with its own coords) back to the source key via the DHT. When the source receives the ack, they send a ping via the tree, and the dest replies along the reverse route. This learns the `S->D` path with a 3-way trip (if we count the initial DHT routed packet as happening for free).

I'm currently leaning towards the 4th version of path discovery. It doesn't add any overhead to the DHT packets, and the sender doesn't spam the network with path discovery packets in the case where the destination key isn't in use (either because the node is offline or because the sender doesn't know the full key yet).

Regardless of which version of path discovery is used, we'd probably want to add ygg-like port numbers to each peer link, to keep the nodes involved in the path private (and keep the size of the lookup packets small -- coords could be in ygg-like format instead of a long list of signed messages).

Note that the example application would need updating for source routing to work (currently it sends to partial keys, it would need to build a cache of full keys from traffic it receives, and then use them to send reply traffic).

