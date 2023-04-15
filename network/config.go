package network

import (
	"crypto/ed25519"
	"time"
)

type config struct {
	routerRefresh      time.Duration
	routerTimeout      time.Duration
	routerMaxInfos     uint64
	peerKeepAliveDelay time.Duration
	peerTimeout        time.Duration
	peerPingIncrement  time.Duration
	peerPingMaxDelay   time.Duration
	peerMaxMessageSize uint64
	pathTransform      func(ed25519.PublicKey) ed25519.PublicKey
	pathNotify         func(ed25519.PublicKey)
	pathTimeout        time.Duration
	pathThrottle       time.Duration
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
		c.pathTransform = func(key ed25519.PublicKey) ed25519.PublicKey { return key }
		c.pathNotify = func(key ed25519.PublicKey) {}
		c.pathTimeout = time.Minute
		c.pathThrottle = time.Second
	}
}

func WithRouterRefresh(duration time.Duration) Option {
	return func(c *config) {
		c.routerRefresh = duration
	}
}

func WithRouterTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.routerTimeout = duration
	}
}

func WithRouterMaxEntries(entries uint64) Option {
	return func(c *config) {
		c.routerMaxInfos = entries
	}
}

func WithPeerKeepAliveDelay(duration time.Duration) Option {
	return func(c *config) {
		c.peerKeepAliveDelay = duration
	}
}

func WithPeerTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.peerTimeout = duration
	}
}

func WithPeerPingIncrement(duration time.Duration) Option {
	return func(c *config) {
		c.peerPingIncrement = duration
	}
}

func WithPeerPingMaxDelay(duration time.Duration) Option {
	return func(c *config) {
		c.peerPingMaxDelay = duration
	}
}

func WithPeerMaxMessageSize(size uint64) Option {
	return func(c *config) {
		c.peerMaxMessageSize = size
	}
}

func WithPathTransform(xform func(key ed25519.PublicKey) ed25519.PublicKey) Option {
	return func(c *config) {
		c.pathTransform = xform
	}
}

func WithPathNotify(notify func(key ed25519.PublicKey)) Option {
	return func(c *config) {
		c.pathNotify = notify
	}
}

func WithPathTimeout(duration time.Duration) Option {
	return func(c *config) {
		c.pathTimeout = duration
	}
}

func WithPathThrottle(duration time.Duration) Option {
	return func(c *config) {
		c.pathThrottle = duration
	}
}
