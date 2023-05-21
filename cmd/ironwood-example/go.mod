module github.com/Arceliar/ironwood-example

go 1.16

replace github.com/Arceliar/ironwood => ../../

require (
	github.com/Arceliar/ironwood v0.0.0-00010101000000-000000000000
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.9.0
	golang.org/x/sys v0.7.0
	golang.zx2c4.com/wireguard v0.0.20201118
)
