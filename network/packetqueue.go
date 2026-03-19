package network

import (
	"time"
)

const (
	defaultPacketQueueMaxBytesMultiplier = 16
	defaultPacketQueuePerFlowMultiplier  = 4
)

type pqPacket interface {
	wireEncodeable
	wireType() wirePacketType
	sourceKey() publicKey
	destKey() publicKey
}

type pqPacketInfo struct {
	packet pqPacket
	size   uint64
	time   time.Time
}

type pqFlowKey struct {
	source publicKey // Original sender for this queued flow
	dest   publicKey // Intended receiver for this queued flow
}

type pqFlow struct {
	key     pqFlowKey      // Stable flow identity used in the queue map
	infos   []pqPacketInfo // FIFO packet backlog for this flow
	size    uint64         // Total queued bytes currently held by this flow
	deficit uint64         // DRR credit used to decide which flow can send next
	index   int            // Position in q.active or -1 when inactive
}

type packetQueue struct {
	flows           map[pqFlowKey]*pqFlow // All known flows, keyed by source/dest pair
	active          []*pqFlow             // Flows that currently have queued packets
	next            int                   // Round-robin cursor into active flows
	size            uint64                // Total queued bytes across all active flows
	maxBytesTotal   uint64                // Hard cap for total queued bytes
	maxBytesPerFlow uint64                // Hard cap for bytes a single flow may hold
	quantum         uint64                // DRR byte budget added to a flow each round
}

func (q *packetQueue) init(pmtu uint64) {
	if pmtu == 0 {
		pmtu = defaultMaxMessageSize
	}
	q.flows = make(map[pqFlowKey]*pqFlow)
	q.next = -1
	q.quantum = pmtu
	q.maxBytesTotal = q.quantum * defaultPacketQueueMaxBytesMultiplier
	q.maxBytesPerFlow = q.quantum * defaultPacketQueuePerFlowMultiplier
}

func (q *packetQueue) activate(flow *pqFlow) {
	flow.index = len(q.active)
	q.active = append(q.active, flow)
}

func (q *packetQueue) deactivate(flow *pqFlow) {
	idx := flow.index
	last := len(q.active) - 1
	if idx < 0 || idx > last {
		return
	}
	if idx != last {
		moved := q.active[last]
		q.active[idx] = moved
		moved.index = idx
	}
	q.active[last] = nil
	q.active = q.active[:last]
	flow.index = -1
	if len(q.active) == 0 {
		q.next = -1
		return
	}
	if q.next == last {
		q.next = idx
	}
	if q.next >= len(q.active) {
		q.next = 0
	}
}

func (q *packetQueue) flowFor(packet pqPacket) *pqFlow {
	key := pqFlowKey{source: packet.sourceKey(), dest: packet.destKey()}
	if flow, ok := q.flows[key]; ok {
		return flow
	}
	flow := &pqFlow{key: key, index: -1}
	q.flows[key] = flow
	return flow
}

func (q *packetQueue) removeFlowIfEmpty(flow *pqFlow) {
	if len(flow.infos) != 0 {
		return
	}
	if flow.index >= 0 {
		q.deactivate(flow)
	}
	delete(q.flows, flow.key)
}

func (q *packetQueue) dropFrom(flow *pqFlow) (pqPacketInfo, bool) {
	if flow == nil || len(flow.infos) == 0 {
		return pqPacketInfo{}, false
	}
	info := flow.infos[0]
	n := copy(flow.infos, flow.infos[1:])
	flow.infos[n] = pqPacketInfo{}
	flow.infos = flow.infos[:n]
	flow.size -= info.size
	q.size -= info.size
	if flow.deficit > q.quantum*4 {
		flow.deficit = q.quantum * 4
	}
	q.removeFlowIfEmpty(flow)
	return info, true
}

func (q *packetQueue) largestFlow() *pqFlow {
	var victim *pqFlow
	for _, flow := range q.active {
		if victim == nil || flow.size > victim.size ||
			(flow.size == victim.size && flow.infos[0].time.Before(victim.infos[0].time)) {
			victim = flow
		}
	}
	return victim
}

func freePQPacket(packet pqPacket) {
	switch p := packet.(type) {
	case *traffic:
		freeTraffic(p)
	default:
		// Nothing to do
	}
}

// drop will remove a packet from the queue.
// The packet removed will be the oldest packet from the largest flow.
// Returns true if a packet was removed, false otherwise.
func (q *packetQueue) drop() bool {
	if q.size == 0 {
		return false
	}
	victim := q.largestFlow()
	info, ok := q.dropFrom(victim)
	if !ok {
		return false
	}
	freePQPacket(info.packet)
	return true
}

// push adds a packet with the provided size to a flow-specific queue.
// The queue is hard-bounded in bytes globally and per flow.
func (q *packetQueue) push(packet pqPacket) {
	upsz := uint64(packet.size())
	if upsz > q.maxBytesTotal || upsz > q.maxBytesPerFlow {
		freePQPacket(packet)
		return
	}
	info := pqPacketInfo{
		packet: packet,
		size:   upsz,
		time:   time.Now(),
	}
	// Check that we aren't overflowing that particular queue.
	flow := q.flowFor(packet)
	for flow.size+info.size > q.maxBytesPerFlow && len(flow.infos) > 0 {
		dropped, ok := q.dropFrom(flow)
		if !ok {
			freePQPacket(packet)
			return
		}
		freePQPacket(dropped.packet)
	}
	// Check that we aren't overflowing the maximum queued total.
	for q.size+info.size > q.maxBytesTotal && q.size > 0 {
		if !q.drop() {
			freePQPacket(packet)
			return
		}
	}
	// The flow may have been removed while making room above; reacquire the
	// registered flow before appending the new packet.
	flow = q.flowFor(packet)
	flow.infos = append(flow.infos, info)
	flow.size += info.size
	q.size += info.size
	if flow.index < 0 {
		q.activate(flow)
	}
}

// pop removes and returns the next packet using deficit round robin across flows.
func (q *packetQueue) pop() (info pqPacketInfo, ok bool) {
	if q.size == 0 || len(q.active) == 0 {
		q.next = -1
		return
	}
	needCredit := false
	if q.next < 0 {
		q.next = 0
		needCredit = true
	} else if q.next >= len(q.active) {
		q.next = 0
	}
	flow := q.active[q.next]
	if needCredit {
		flow.deficit += q.quantum
	}
	for {
		if len(flow.infos) > 0 && flow.infos[0].size <= flow.deficit {
			info, ok := q.dropFrom(flow)
			if ok {
				flow.deficit -= info.size
			}
			return info, ok
		}
		if q.next++; q.next >= len(q.active) {
			q.next = 0
		}
		flow = q.active[q.next]
		flow.deficit += q.quantum
	}
}

func (q *packetQueue) peek() (info pqPacketInfo, ok bool) {
	var oldest *pqPacketInfo
	for _, flow := range q.active {
		if len(flow.infos) == 0 {
			continue
		}
		head := &flow.infos[0]
		if oldest == nil || head.time.Before(oldest.time) {
			oldest = head
		}
	}
	if oldest != nil {
		return *oldest, true
	}
	return
}
