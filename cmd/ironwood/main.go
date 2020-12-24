package main

import (
	"crypto/ed25519"

	inet "github.com/Arceliar/ironwood/net"
)

func main() {
	// Dummy
	_, priv, _ := ed25519.GenerateKey(nil)
	_, _ = inet.NewPacketConn(priv)
}
