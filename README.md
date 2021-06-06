# Ironwood

A project description will come later. Ironwood is pre-alpha work-in-progress. That means the API is unstable, and it's not expected to be fit for use for any purpose. Use at your own risk.

## TODO

The following is a very rough TODO of what still needs to be implemented before this project is feature complete enough that it's worth calling it alpha / tagging whenever backwards compatibility breaks.

### Misc optimizations

There are lots of places in the code where we do something stupid but easy to write, instead of doing things the right way.
We should do things right. That usually means computing some things once, then holding on to the result (in read-only form, possibly distributing this to other actors) so we can reuse it without wasting resources.
E.g. pre-compute a DHT lookup table (use a radix trie or something) instead of looping over *everything* for every packet we're asked to forward.

### Wire formats

Currently the data structures that need to be sent over the wire are marshaled and unmarshaled by hand-written functions.
In the interest of clarity, it would *probably* make sense to just pick some well(-ish) known serialization format, and use that instead, even if it's slower.
There are a lot of options here, but all else being equal, clarity probably matters more than efficiency of the default implementation (since we could hand-write a parser to cover the special cases where we need to peek at something in-place for efficiency reasons).
All else being equal, it's probably preferable to use something well-known rather than something that wins in benchmarks, so protocol buffers are probably a good default option for lack of better ideas.
But it warrants further investigation.

### Expand DHT functionality

Currently the out-of-band code lets you notify the node that own an arbitrary key (and they can choose whether or not to respond, based on if/how they've set their handler).
To make it easier to implement a generic DHT, a node needs to be able to tell the PacketConn that it thinks it owns a key, and provide a handler for the PC to call if/when it no longer owns it (when we get a connection to a better owner).
This isn't high priority from a ygg-replacement standpoint (it's not needed for that use case), but it would be relatively easy to do and it could be generally nice to have.

### Protocol update(s)

1. Investigate keeping a second keyspace neighbor in each direction, so the chain isn't momentarily broken when a node joins. NOTE: Investigated, ultimately I think we'll need two neighbors per side + a different path setup order (path from next before path to prev), to prevent momentary disruption to the DHT when a node joins or leaves. Implementing/debugging/etc turns out to be more complicated than initially expected, so this is unlikely to happen until other things are in place and the existing code has been field tested.
2. ~The encrypted package could use some work... either switch to the noise protocol framework, or improve what's already there (to e.g. not send ephemeral pubkeys in plaintext).~
Done, traffic ephemeral keys are kept out of cleartext, among other improvements.

### DEBUG interface

~Some sort of debug interface is needed, to get read access to the low level internals. This (probably) doesn't need to be a stable API endpoint. It would be useful (in the ygg context) to e.g. check a node's coords, get a list of peers (with ports), dump out the full set of DHT info, etc.~
Done, but there's still some room for improvement.

