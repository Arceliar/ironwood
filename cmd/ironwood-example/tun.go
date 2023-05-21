package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	iwt "github.com/Arceliar/ironwood/types"
)

func setupTun(ifname, address string) tun.Device {
	dev, err := tun.CreateTUN(ifname, 1500)
	if err != nil {
		panic(err)
	}
	nladdr, err := netlink.ParseAddr(address)
	if err != nil {
		panic(err)
	}
	name, err := dev.Name()
	if err != nil {
		panic(err)
	}
	nlintf, err := netlink.LinkByName(name)
	if err != nil {
		panic(err)
	} else if err := netlink.AddrAdd(nlintf, nladdr); err != nil {
		panic(err)
	} else if err := netlink.LinkSetMTU(nlintf, 1500); err != nil {
		panic(err)
	} else if err := netlink.LinkSetUp(nlintf); err != nil {
		panic(err)
	}
	return dev
}

const tunOffsetBytes = 4

func tunReader(dev tun.Device, pc iwt.PacketConn) {
	localAddr := pc.LocalAddr()
	pubKey := ed25519.PublicKey(localAddr.(iwt.Addr))
	addrBytes := getAddr(pubKey)
	buf := make([]byte, 2048)
	for {
		n, err := dev.Read(buf, tunOffsetBytes)
		if err != nil {
			panic(err)
		}
		if n <= tunOffsetBytes {
			panic("tunOffsetBytes")
		}
		bs := buf[tunOffsetBytes : tunOffsetBytes+n]
		if len(bs) < 40 {
			panic("undersized packet")
		}
		var srcAddr, dstAddr [16]byte
		copy(srcAddr[:], bs[8:24])
		copy(dstAddr[:], bs[24:40])
		if srcAddr != addrBytes {
			//panic("wrong source address")
			continue
		}
		if dstAddr[0] != 0xfd {
			//panic("wrong dest subnet")
			continue
		}
		destKey, isGood := getKey(dstAddr)
		//destKey, isGood := getTargetKey(dstAddr)
		if !isGood {
			destKey, _ := getTargetKey(dstAddr)
			pc.SendLookup(destKey)
			pushBufMsg(dstAddr, bs)
			continue
		}
		//destKey = pc.GetKeyFor(destKey)
		if !checkKey(dstAddr, destKey) {
			continue
		}
		if isGood {
			dest := iwt.Addr(destKey)
			n, err = pc.WriteTo(bs, dest)
			if err != nil {
				panic(err)
			}
			if n != len(bs) {
				panic("failed to write full packet to packetconn")
			}
		}
	}
}

func tunWriter(dev tun.Device, pc net.PacketConn) {
	localAddr := pc.LocalAddr()
	pubKey := ed25519.PublicKey(localAddr.(iwt.Addr))
	addrBytes := getAddr(pubKey)
	rawBuf := make([]byte, 2048)
	for {
		buf := rawBuf
		n, remote, err := pc.ReadFrom(buf[tunOffsetBytes:])
		if err != nil {
			panic(err)
		}
		if n < 40 {
			panic("undersized packet")
		}
		buf = buf[:tunOffsetBytes+n]
		bs := buf[tunOffsetBytes : tunOffsetBytes+n]
		var srcAddr, dstAddr [16]byte
		copy(srcAddr[:], bs[8:24])
		copy(dstAddr[:], bs[24:40])
		if srcAddr[0] != 0xfd {
			fmt.Println(net.IP(srcAddr[:]).String()) // FIXME
			panic("wrong source subnet")
			continue
		}
		if dstAddr[0] != 0xfd {
			panic("wrong dest subnet")
			continue
		}
		if dstAddr != addrBytes {
			panic("wrong dest addr")
			continue
		}
		remoteKey := ed25519.PublicKey(remote.(iwt.Addr))
		if !checkKey(srcAddr, remoteKey) {
			continue
		}
		//putKey(remoteKey)
		n, err = dev.Write(buf, tunOffsetBytes)
		if err != nil {
			panic(err)
		}
		if n != len(buf) {
			panic("wrong number of bytes written")
		}
	}
}

var keyMutex sync.Mutex
var keyMap map[[16]byte]*keyInfo

type keyInfo struct {
	key   ed25519.PublicKey
	timer *time.Timer
}

func putKey(key ed25519.PublicKey) {
	addr := getAddr(key)
	info := new(keyInfo)
	info.key = ed25519.PublicKey(append([]byte(nil), key...))
	info.timer = time.AfterFunc(time.Minute, func() {
		keyMutex.Lock()
		defer keyMutex.Unlock()
		delete(keyMap, addr)
	})
	keyMutex.Lock()
	defer keyMutex.Unlock()
	if keyMap == nil {
		keyMap = make(map[[16]byte]*keyInfo)
	}
	if old, isIn := keyMap[addr]; isIn {
		old.timer.Stop()
	}
	keyMap[addr] = info
}

func getTargetKey(addr [16]byte) (ed25519.PublicKey, bool) {
	destKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	copy(destKey, addr[1:])
	for idx := range destKey {
		destKey[idx] = ^destKey[idx]
	}
	return destKey, true
}

func getKey(addr [16]byte) (ed25519.PublicKey, bool) {
	keyMutex.Lock()
	info := keyMap[addr]
	keyMutex.Unlock()
	if info != nil {
		//fmt.Println("Found key", net.IP(addr).String(), info.key)
		return info.key, true
	}
	destKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	copy(destKey, addr[1:])
	for idx := range destKey {
		destKey[idx] = ^destKey[idx]
	}
	return destKey, false
}

func checkKey(addr [16]byte, key ed25519.PublicKey) bool {
	tmp := addr
	for idx := range tmp {
		tmp[idx] = ^tmp[idx]
	}
	return bytes.Equal(tmp[1:], key[:len(addr)-1])
}

func getAddr(key ed25519.PublicKey) (addr [16]byte) {
	copy(addr[1:], key)
	for idx := range addr {
		addr[idx] = ^addr[idx]
	}
	addr[0] = 0xfd
	return
}

func transformKey(key ed25519.PublicKey) ed25519.PublicKey {
	addr := getAddr(key)
	xform, _ := getTargetKey(addr)
	return xform
}

// Buffer traffic while waiting for a key

var bufMutex sync.Mutex
var bufMap map[[16]byte]*bufInfo

type bufInfo struct {
	msg   []byte
	timer *time.Timer
}

func pushBufMsg(addr [16]byte, msg []byte) {
	info := new(bufInfo)
	info.msg = append(info.msg, msg...)
	bufMutex.Lock()
	defer bufMutex.Unlock()
	if bufMap == nil {
		bufMap = make(map[[16]byte]*bufInfo)
	}
	old := bufMap[addr]
	bufMap[addr] = info
	info.timer = time.AfterFunc(time.Minute, func() {
		bufMutex.Lock()
		defer bufMutex.Unlock()
		if n := bufMap[addr]; n == info {
			delete(bufMap, addr)
		}
	})
	if old != nil {
		old.timer.Stop()
	}
}

func popBufMsg(addr [16]byte) []byte {
	bufMutex.Lock()
	defer bufMutex.Unlock()
	if info := bufMap[addr]; info != nil {
		info.timer.Stop()
		return info.msg
	}
	return nil
}

const (
	oobKeyReq = 1
	oobKeyRes = 2
)

func flushBuffer(pc net.PacketConn, destKey ed25519.PublicKey) {
	addr := getAddr(destKey)
	if bs := popBufMsg(addr); bs != nil {
		dest := iwt.Addr(destKey)
		n, err := pc.WriteTo(bs, dest)
		if err != nil {
			panic(err)
		}
		if n != len(bs) {
			panic("failed to write full packet to packetconn")
		}
	}
}
