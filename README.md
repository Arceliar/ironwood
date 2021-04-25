# Ironwood

A project description will come later. Ironwood is pre-alpha work-in-progress and is not expected to be fit for purpose for any use case.

## TODO

The following is a very rough TODO of what still needs to be implemented before this project is feature complete enough that it's worth testing (as are replacement to ygg's core or as a stand-alone network or something).

### Drop packets

Currently there's no way to drop any packets when under congestion. Things just buffer in actor message queues forever.
That's *intended* for a few kinds of protocol traffic, where dropping anything could lead to inconsistency and routing loops.
It's a problem for ordinary traffic being forwarded through the network (and arguably certain non-local protocol traffic).
We've implemented variations of this before in Ygg, we just need to pick something and go with it.

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
