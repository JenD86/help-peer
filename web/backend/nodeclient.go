package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// Volunteer storage nodes register themselves, so their URLs are chosen by
// strangers. Requests to them must never reach this server's own network
// (the relay, cloud metadata services, other containers), or registration
// would let anyone make the backend send requests to internal services.

var errPrivateAddress = errors.New("refusing to connect to a private or internal address")

// cgnat is 100.64.0.0/10 (carrier-grade NAT), which net.IP doesn't classify.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// isPublicIP reports whether ip is a globally routable unicast address.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		if ip4[0] == 0 || cgnat.Contains(ip4) {
			return false
		}
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// newNodeClient returns an HTTP client for volunteer nodes. The address is
// checked when each connection is made, after DNS resolution, so a hostname
// can't pass registration and later resolve to an internal address.
func newNodeClient(allowPrivate bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if !isPublicIP(net.ParseIP(host)) {
				return fmt.Errorf("%w: %s", errPrivateAddress, host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil, // never route through an environment proxy
			DialContext:         dialer.DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
		// A node redirecting elsewhere could point at an internal address;
		// the dialer would refuse it, but there's no reason to follow at all.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
