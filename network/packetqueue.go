package network

import (
	"container/heap"
	"time"
)

type pqStreamID struct {
	source publicKey
	dest   publicKey
}

type pqPacketInfo struct {
	packet wireEncodeable
	size   uint64
	time   time.Time
}

type pqStream struct {
	id    pqStreamID
	infos []pqPacketInfo
	size  uint64
}

type packetQueue struct {
	streams []pqStream
	size    uint64
}

// drop will remove a packet from the queue
// the packet removed will be the oldest packet from the largest stream
// returns true if a packet was removed, false otherwise
func (q *packetQueue) drop() bool {
	if q.size == 0 {
		return false
	}
	var longestIdx int
	for idx := range q.streams {
		if q.streams[idx].size > q.streams[longestIdx].size {
			longestIdx = idx
		}
	}
	stream := q.streams[longestIdx]
	info := stream.infos[0]
	if len(stream.infos) > 1 {
		stream.infos = stream.infos[1:]
		stream.size -= info.size
		q.streams[longestIdx] = stream
		q.size -= info.size
		heap.Fix(q, longestIdx)
	} else {
		heap.Remove(q, longestIdx)
	}
	return true
}

// push adds a packet with the provided size to a queue with the provided id
// a new queue for the stream id will be created if needed
func (q *packetQueue) push(id pqStreamID, packet wireEncodeable, size int) {
	info := pqPacketInfo{packet: packet, size: uint64(size), time: time.Now()}
	for idx := range q.streams {
		if q.streams[idx].id == id {
			q.streams[idx].infos = append(q.streams[idx].infos, info)
			q.streams[idx].size += info.size
			q.size += info.size
			return
		}
	}
	stream := pqStream{id: id, size: info.size}
	stream.infos = append(stream.infos, info)
	heap.Push(q, stream)
}

// pop removes the oldest packet (across all streams) from the queue
func (q *packetQueue) pop() (info pqPacketInfo, ok bool) {
	if q.size > 0 {
		stream := q.streams[0]
		info = stream.infos[0]
		if len(stream.infos) > 1 {
			stream.infos = stream.infos[1:]
			stream.size -= info.size
			q.streams[0] = stream
			q.size -= info.size
			heap.Fix(q, 0)
		} else {
			heap.Remove(q, 0)
		}
		return info, true
	}
	return
}

func (q *packetQueue) peek() (info pqPacketInfo, ok bool) {
	if len(q.streams) > 0 {
		stream := q.streams[0]
		info = stream.infos[0]
		return info, true
	}
	return
}

////////////////////////////////////////////////////////////////////////////////

// Interface methods for packetQueue to satisfy heap.Interface

func (q *packetQueue) Len() int {
	return len(q.streams)
}

func (q *packetQueue) Less(i, j int) bool {
	return q.streams[i].infos[0].time.Before(q.streams[j].infos[0].time)
}

func (q *packetQueue) Swap(i, j int) {
	q.streams[i], q.streams[j] = q.streams[j], q.streams[i]
}

func (q *packetQueue) Push(x interface{}) {
	stream := x.(pqStream)
	q.streams = append(q.streams, stream)
	q.size += stream.size
}

func (q *packetQueue) Pop() interface{} {
	idx := len(q.streams) - 1
	stream := q.streams[idx]
	q.streams = q.streams[:idx]
	q.size -= stream.size
	return stream
}
