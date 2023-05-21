package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	iwt "github.com/Arceliar/ironwood/types"
)

const listenAddrString = ":12345"
const groupAddrString = "[ff02::114]:12345"

var groupAddr *net.UDPAddr

var connectionsMutex sync.RWMutex
var connections map[string]net.Conn

func init() {
	var err error
	if groupAddr, err = net.ResolveUDPAddr("udp6", groupAddrString); err != nil {
		panic(err)
	}
	connections = make(map[string]net.Conn)
}

func newMulticastConn() *ipv6.PacketConn {
	reuse := func(network, address string, c syscall.RawConn) (err error) {
		_ = c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
		return
	}
	lc := net.ListenConfig{
		Control: reuse,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", listenAddrString)
	if err != nil {
		panic(err)
	}
	mc := ipv6.NewPacketConn(conn)
	return mc
}

func mcSender(mc *ipv6.PacketConn, key ed25519.PublicKey) {
	intfs, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, intf := range intfs {
		addrs, err := intf.Addrs()
		if err != nil {
			panic(err)
		}
		for _, addr := range addrs {
			addrIP, _, _ := net.ParseCIDR(addr.String())
			if addrIP.To4() != nil {
				continue
			} else if !addrIP.IsLinkLocalUnicast() {
				continue
			}
			tmp := intf
			_ = mc.JoinGroup(&tmp, groupAddr)
			destAddr, err := net.ResolveUDPAddr("udp6", groupAddrString)
			if err != nil {
				panic(err)
			}
			destAddr.Zone = tmp.Name
			_, _ = mc.WriteTo(key, nil, destAddr)
			break
		}
	}
	time.AfterFunc(3*time.Second, func() { mcSender(mc, key) })
}

func mcListener(mc *ipv6.PacketConn, key ed25519.PublicKey, pc iwt.PacketConn) {
	for {
		bs := make([]byte, 2048)
		n, _, from, err := mc.ReadFrom(bs)
		if err != nil {
			panic(err)
		}
		if n != ed25519.PublicKeySize {
			continue
		}
		if bytes.Equal(bs[:n], key) {
			continue
		}
		go func() {
			destKey := ed25519.PublicKey(bs[:n])
			destKeyString := iwt.Addr(destKey).String()
			tcpAddr := new(net.TCPAddr)
			uAddr := from.(*net.UDPAddr)
			tcpAddr.IP = uAddr.IP
			tcpAddr.Port = 12345
			tcpAddr.Zone = uAddr.Zone
			var isIn bool
			connectionsMutex.RLock()
			_, isIn = connections[destKeyString]
			connectionsMutex.RUnlock()
			if isIn {
				return
			}
			conn, err := net.DialTimeout(tcpAddr.Network(), tcpAddr.String(), time.Second)
			if err != nil {
				//panic(err)
				return
			}
			conn.(*net.TCPConn).SetKeepAlive(true)
			handleTCP(pc, conn)
		}()
	}
}

func handleTCP(pc iwt.PacketConn, conn net.Conn) {
	defer conn.Close()
	localAddr := pc.LocalAddr()
	pubKey := ed25519.PublicKey(localAddr.(iwt.Addr))
	if _, err := conn.Write(pubKey); err != nil {
		fmt.Println("Error writing our key:", err)
		return
	}
	there := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, there); err != nil {
		fmt.Println("Error reading remote key:", err)
		return
	}
	destKeyString := iwt.Addr(there).String() // TODO? check this against key from UDP announcement
	connectionsMutex.Lock()
	if _, isIn := connections[destKeyString]; isIn {
		connectionsMutex.Unlock()
		return
	}
	connections[destKeyString] = conn
	connectionsMutex.Unlock()
	addrBytes := make([]byte, 16)
	addrBytes[0] = 0xfd
	copy(addrBytes[1:], there)
	for idx := 1; idx < len(addrBytes); idx++ {
		addrBytes[idx] = ^addrBytes[idx]
	}
	ip := net.IP(addrBytes)
	fmt.Println("Connected to", ip.String())
	if err := pc.HandleConn(there, conn, 0); err != nil {
		fmt.Println("Disconnected from", ip.String(), "due to:", err)
	} else {
		fmt.Println("Disconnected from", ip.String())
	}
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()
	delete(connections, destKeyString)
}

func listenTCP(pc iwt.PacketConn) {
	listener, err := net.Listen("tcp", listenAddrString)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go handleTCP(pc, conn)
	}
}
