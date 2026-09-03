package relay

import (
	"fmt"
	"net"
	"net/netip"
)

// Mode represents the operational mode of an interface in the relay daemon.
// This daemon only ever relays, so the only real states are "disabled"
// (interface currently torn down, e.g. because its link is down or there is no
// peer to relay with) and "relay".
type Mode int

const (
	ModeDisabled Mode = iota
	ModeRelay
)

// IPAddr represents one IPv4 address assigned to an interface, with its
// prefix length.
type IPAddr struct {
	Addr      netip.Addr
	PrefixLen uint8
	Tentative bool // IPv4 DAD (arping-style duplicate detection) in progress
}

// Interface represents a network interface. All fields are only ever read or
// written from the single Engine goroutine (see engine.go), so no locking
// is required here.
type Interface struct {
	Name    string // config key, e.g. "wan"
	Ifname  string // real netdev name, e.g. "eth0"
	Ifindex int
	Running bool // IFF_RUNNING (carrier up)
	Master  bool

	LearnRoutes bool // install /32 host routes for mirrored neighbors
	Inuse       bool

	Addr4 []IPAddr

	DHCPv4 Mode
	ARP    Mode

	dhcp *dhcpSock
}

// interfaces holds every configured interface keyed by its config name.
// Only ever touched from the Engine goroutine.
var interfaces = map[string]*Interface{}

func ifaceByIndex(idx int) *Interface {
	for _, i := range interfaces {
		if i.Ifindex == idx {
			return i
		}
	}
	return nil
}

func ifaceByIfname(name string) *Interface {
	for _, i := range interfaces {
		if i.Ifname == name {
			return i
		}
	}
	return nil
}

// setInterfaceDefaults resets the service configuration of an interface:
// this daemon relays everything by default.
func setInterfaceDefaults(i *Interface) {
	i.DHCPv4 = ModeRelay
	i.ARP = ModeRelay
	i.LearnRoutes = true
}

// getMAC returns the hardware (MAC) address of the interface.
func getMAC(iface *Interface) (net.HardwareAddr, error) {
	nif, err := net.InterfaceByName(iface.Ifname)
	if err != nil {
		return nil, err
	}
	if len(nif.HardwareAddr) < 6 {
		return nil, fmt.Errorf("interface %s has no hardware address", iface.Ifname)
	}
	return nif.HardwareAddr, nil
}

// relayLinkAddress4 picks the interface's primary IPv4 address, used as the
// giaddr when relaying client requests out a master interface: the upstream
// DHCP server selects the lease pool from the giaddr subnet and sends its
// replies back to it. Skips tentative (DAD-in-progress) and non-unicast
// addresses; returns false when the interface has no usable IPv4 address yet.
func relayLinkAddress4(iface *Interface) (netip.Addr, bool) {
	for _, a := range iface.Addr4 {
		if a.Tentative || !a.Addr.Is4() {
			continue
		}
		if a.Addr.IsLoopback() || a.Addr.IsLinkLocalUnicast() || a.Addr.IsMulticast() {
			continue
		}
		return a.Addr, true
	}
	return netip.Addr{}, false
}