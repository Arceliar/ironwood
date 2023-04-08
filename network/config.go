package network

import "time"

type config struct {
	routerRefresh      time.Duration
	routerTimeout      time.Duration
	routerMaxInfos     uint64
	peerKeepAliveDelay time.Duration
	peerTimeout        time.Duration
	peerPingIncrement  time.Duration
	peerPingMaxDelay   time.Duration
	peerMaxMessageSize uint64
}

type Option func(*config)

func configDefaults() Option {
	return func(c *config) {
		c.routerRefresh = 23 * time.Hour
		c.routerTimeout = 23 * time.Hour
		c.routerMaxInfos = 65535
		c.peerKeepAliveDelay = time.Second
		c.peerTimeout = 3 * time.Second
		c.peerPingIncrement = time.Second
		c.peerPingMaxDelay = time.Minute
		c.peerMaxMessageSize = 1048576 // 1 megabyte
	}
}
