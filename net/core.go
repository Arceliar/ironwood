package net

type core struct {
	crypto crypto      // crypto info, e.g. pubkeys and sign/verify wrapper functions
	tree   tree        // spanning tree
	dht    interface{} // distributed hash table
	peers  interface{} // info about peers (from HandleConn), makes routing decisions and passes protocol traffic to relevant parts of the code
	router interface{} // handles traffic to/from the user's application code, contains the underlying logic for the exported net.PacketConn interface
	pconn  packetConn  // net.PacketConn-like interface
}
