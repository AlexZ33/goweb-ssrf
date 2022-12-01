package goweb_ssrf

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	ranges []string = []string{
		"0.0.0.0/32",         // Current network (only valid as source address)
		"240.0.0.0/4",        // Reserved for future use
		"203.0.113.0/24",     // Assigned as TEST-NET-3
		"198.51.100.0/24",    // Assigned as TEST-NET-2, documentation and examples
		"198.18.0.0/15",      // Used for benchmark testing of inter-network communications between two separate subnets
		"192.0.2.0/24",       // Assigned as TEST-NET-1, documentation and examples
		"100.64.0.0/10",      // Shared address space for communications between a service provider and its subscribers when using a carrier-grade NAT.
		"255.255.255.255/32", // Reserved for the "limited broadcast" destination address
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // Assigned as TEST-NET-1, documentation and examples
		"192.88.99.0/24",     // Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16)
		"192.168.0.0/16",     // Used for local communications within a private network
		"172.16.0.0/12",      // Used for local communications within a private network
		"10.0.0.0/8",         // Used for local communications within a private network
		"127.0.0.0/8",        // Used for loopback addresses to the local host
		"169.254.0.0/16",     // Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified
		"224.0.0.0/4",        // In use for IP multicast.[9] (Former Class D network)
	}
	blacklist []net.IPNet = createBlacklist()
)

func createBlacklist() []net.IPNet {
	b := []net.IPNet{}
	for _, sCIDR := range ranges {
		_, c, _ := net.ParseCIDR(sCIDR)
		b = append(b, *c)
	}
	return b
}

func isAllowed(sIP string) bool {
	for _, r := range blacklist {
		if r.Contains(net.ParseIP(sIP)) {
			return false
		}
	}
	return true
}

func ssrf() {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (conn net.Conn, err error) {
			s := strings.LastIndex(addr, ":")
			IPs, err := net.LookupHost(addr[:s])
			if err != nil {
				return nil, err
			}
			for _, IP := range IPs {
				if !isAllowed(IP) {
					err = errors.New("IP not allowed")
					return
				}

				conn, err = net.Dial(network, IP+addr[s:])
				if err == nil {
					break
				}
			}
			return
		},
	}

	var client = &http.Client{
		Transport: tr,
		Timeout:   time.Duration(5 * time.Second),
	}

	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		log.Println(err)
		return
	}
	_, err = client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
}
