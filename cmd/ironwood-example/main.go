package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	iwc "github.com/Arceliar/ironwood/encrypted"
	iwn "github.com/Arceliar/ironwood/network"
	iws "github.com/Arceliar/ironwood/signed"
	iwt "github.com/Arceliar/ironwood/types"

	"log"
	"net/http"
	_ "net/http/pprof"
)

var ifname = flag.String("ifname", "\000", "interface name to bind to")
var pprof = flag.String("pprof", "", "listen to pprof on this port")
var enc = flag.Bool("enc", false, "encrypt traffic (must be enabled on all nodes)")
var sign = flag.Bool("sign", false, "sign traffic (must be enabled on all nodes)")

func main() {
	flag.Parse()
	if pprof != nil && *pprof != "" {
		go func() {
			log.Println(http.ListenAndServe(*pprof, nil))
		}()
	}
	_, key, _ := ed25519.GenerateKey(nil)
	var pc iwt.PacketConn
	var opts []iwn.Option
	var doNotify2 func(key ed25519.PublicKey)
	doNotify1 := func(key ed25519.PublicKey) {
		doNotify2(key)
	}
	opts = append(opts, iwn.WithBloomTransform(transformKey))
	opts = append(opts, iwn.WithPathNotify(doNotify1))
	if *enc && *sign {
		panic("TODO a useful error message (can't use both -unenc and -sign)")
	} else if *enc {
		pc, _ = iwc.NewPacketConn(key, opts...)
	} else if *sign {
		pc, _ = iws.NewPacketConn(key, opts...)
	} else {
		pc, _ = iwn.NewPacketConn(key, opts...)
	}
	defer pc.Close()
	doNotify2 = func(key ed25519.PublicKey) {
		putKey(key)
		flushBuffer(pc, key) // Ugly hack, we need the pc for flushBuffer to work
	}
	// get address and pc.SetOutOfBandHandler
	localAddr := pc.LocalAddr()
	pubKey := ed25519.PublicKey(localAddr.(iwt.Addr))
	addrBytes := getAddr(pubKey)
	// open tun/tap and assign address
	ip := net.IP(addrBytes[:])
	fmt.Println("Our IP address is", ip.String())
	if ifname != nil && *ifname != "none" {
		tun := setupTun(*ifname, ip.String()+"/8")
		// read/write between tun/tap and packetconn
		go tunReader(tun, pc)
		go tunWriter(tun, pc)
	}
	// open multicast and start adding peers
	mc := newMulticastConn()
	go mcSender(mc, pubKey)
	go mcListener(mc, pubKey, pc)
	// listen for TCP, pass connections to packetConn.HandleConn
	go listenTCP(pc)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
