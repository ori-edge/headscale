package integration

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ori-edge/headscale/integration/tsic"
)

const (
	derpPingTimeout = 2 * time.Second
	derpPingCount   = 10
)

func pingAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	var success uint32
	var waitGroup sync.WaitGroup

	for _, client := range clients {
		for _, addr := range addrs {
			waitGroup.Add(1)
			go func(client TailscaleClient, addr string) {
				defer waitGroup.Done()

				err := client.Ping(addr)
				if err != nil {
					t.Errorf(
						"failed to ping %s from %s: %s",
						addr,
						client.Hostname(),
						err,
					)
				} else {
					atomic.AddUint32(&success, 1)
				}
			}(client, addr)
		}
	}

	waitGroup.Wait()

	return int(success)
}

func pingDerpAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	var success uint32
	var waitGroup sync.WaitGroup

	for _, client := range clients {
		for _, addr := range addrs {
			if isSelfClient(client, addr) {
				continue
			}

			waitGroup.Add(1)
			go func(client TailscaleClient, addr string) {
				defer waitGroup.Done()

				err := client.Ping(
					addr,
					tsic.WithPingTimeout(derpPingTimeout),
					tsic.WithPingCount(derpPingCount),
					tsic.WithPingUntilDirect(false),
				)
				if err != nil {
					t.Errorf(
						"failed to ping %s from %s: %s",
						addr,
						client.Hostname(),
						err,
					)
				} else {
					atomic.AddUint32(&success, 1)
				}
			}(client, addr)
		}
	}

	waitGroup.Wait()

	return int(success)
}

func isSelfClient(client TailscaleClient, addr string) bool {
	if addr == client.Hostname() {
		return true
	}

	ips, err := client.IPs()
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.String() == addr {
			return true
		}
	}

	return false
}

// pingAllNegativeHelper is intended to have 1 or more nodes timeing out from the ping,
// it counts failures instead of successes.
// func pingAllNegativeHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
// 	t.Helper()
// 	failures := 0
//
// 	timeout := 100
// 	count := 3
//
// 	for _, client := range clients {
// 		for _, addr := range addrs {
// 			err := client.Ping(
// 				addr,
// 				tsic.WithPingTimeout(time.Duration(timeout)*time.Millisecond),
// 				tsic.WithPingCount(count),
// 			)
// 			if err != nil {
// 				failures++
// 			}
// 		}
// 	}
//
// 	return failures
// }

// // findPeerByIP takes an IP and a map of peers from status.Peer, and returns a *ipnstate.PeerStatus
// // if there is a peer with the given IP. If no peer is found, nil is returned.
// func findPeerByIP(
// 	ip netip.Addr,
// 	peers map[key.NodePublic]*ipnstate.PeerStatus,
// ) *ipnstate.PeerStatus {
// 	for _, peer := range peers {
// 		for _, peerIP := range peer.TailscaleIPs {
// 			if ip == peerIP {
// 				return peer
// 			}
// 		}
// 	}
//
// 	return nil
// }
//
// // findPeerByHostname takes a hostname and a map of peers from status.Peer, and returns a *ipnstate.PeerStatus
// // if there is a peer with the given hostname. If no peer is found, nil is returned.
// func findPeerByHostname(
// 	hostname string,
// 	peers map[key.NodePublic]*ipnstate.PeerStatus,
// ) *ipnstate.PeerStatus {
// 	for _, peer := range peers {
// 		if hostname == peer.HostName {
// 			return peer
// 		}
// 	}
//
// 	return nil
// }
