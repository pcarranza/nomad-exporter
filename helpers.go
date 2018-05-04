package main

import (
	"fmt"
	"log"
	"net"
)

func logError(err error) {
	log.Println("Query error", err)
}

// LocalIPs provides an interface to determine if a hostname is localhost
type LocalIPs struct {
	ips map[string]interface{}
}

// NewLocalIPs creates a new LocalIPs with all the ips assigned to local interfaces
func NewLocalIPs() LocalIPs {
	ips := make(map[string]interface{})
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			panic(fmt.Sprintf("could not read addresses for interface %s: %s", iface.Name, err))
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips[ip.String()] = true
		}
	}
	return LocalIPs{
		ips: ips,
	}
}

// IsHostname returns true is the given hostname resolves to a local ip
func (i LocalIPs) IsHostname(hostname string) float64 {
	addresses, err := net.LookupHost(hostname)
	if err != nil {
		return 0
	}
	for _, addr := range addresses {
		if _, ok := i.ips[addr]; ok {
			return 1
		}
	}
	return 0
}
