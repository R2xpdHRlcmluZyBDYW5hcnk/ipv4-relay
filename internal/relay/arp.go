package relay

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// setProxyARP toggles net.ipv4.conf.<ifname>.proxy_arp. The kernel only
// answers ARP requests for our NTF_PROXY entries (and for addresses routed
// via a different interface) while proxy_arp is enabled, so this must stay
// enabled for the whole lifetime of the relay - see reconcileKernelState()
// for why it is periodically re-asserted.
//
// The sysctl is read before writing so a re-assert that finds the value
// already correct (the common case on a debounced reconcile) is a pure read
// with no write - it never touches the value unless it actually differs.
func setProxyARP(ifname string, enable bool) error {
	path := "/proc/sys/net/ipv4/conf/" + ifname + "/proxy_arp"
	want := byte('0')
	if enable {
		want = '1'
	}
	if cur, err := os.ReadFile(path); err == nil {
		if c := bytes.TrimSpace(cur); len(c) == 1 && c[0] == want {
			return nil
		}
	}
	return os.WriteFile(path, []byte{want, '\n'}, 0)
}

// arpSetup toggles the proxy_arp sysctl for the given interface. Unlike the
// IPv6 side (which needs AF_PACKET capture sockets for NS relay), IPv4 proxy
// ARP is answered entirely by the kernel:
//   - on slave interfaces the "routed via a different interface" rule makes
//     the box answer client ARP requests for any upstream address (their
//     default gateway included) with the slave's own MAC;
//   - on master interfaces the NTF_PROXY entries installed per mirrored
//     client (see arpMirrorAddr) make the box answer upstream ARP requests
//     for relayed client addresses with the master's own MAC.
func arpSetup(iface *Interface, enable bool) error {
	enable = enable && iface.ARP != ModeDisabled
	return setProxyARP(iface.Ifname, enable)
}

// arpMirrorAddr installs (or removes) a proxy-ARP entry on every other master
// interface, plus a /32 host route pointing back at the interface the address
// actually lives behind. The host route doubles as the "routed via a
// different interface" condition the kernel needs before it will answer a
// proxied ARP request at all.
func arpMirrorAddr(addr netip.Addr, iface *Interface, add bool) {
	for _, c := range interfaces {
		if c.Ifindex == iface.Ifindex || !c.Master || c.ARP != ModeRelay {
			continue
		}
		// A proxy-ARP entry is inert unless proxy_arp is enabled on its
		// interface, so re-assert it here: this keeps proxy_arp correct even
		// after an external reset (e.g. `netplan apply`) for which no host
		// route existed to trigger handleRouteEvent.
		if add {
			if err := setProxyARP(c.Ifname, true); err != nil {
				Debugf("proxy_arp on %s: %v", c.Ifname, err)
			}
		}
		if err := setupProxyNeigh4(addr, c.Ifindex, add); err != nil {
			Warnf("proxy arp %s on %s: %v", addr, c.Ifname, err)
		}
	}

	if !iface.LearnRoutes || addr.IsLinkLocalUnicast() {
		return
	}

	if err := setupRoute4(addr, 32, iface.Ifindex, ourRouteMetric, add); err != nil {
		Warnf("route %s/32 via %s: %v", addr, iface.Ifname, err)
	}
}

// setupRoute4 adds or removes a route via netlink.
func setupRoute4(addr netip.Addr, prefixlen int, ifindex int, metric int, add bool) error {
	dst := &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(prefixlen, 32)}

	route := &netlink.Route{
		LinkIndex: ifindex,
		Dst:       dst,
		Priority:  metric,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     netlink.SCOPE_LINK,
	}

	if add {
		route.Protocol = unix.RTPROT_STATIC
		return netlink.RouteReplace(route)
	}

	// ESRCH ("no such process") from RouteDel just means the route is
	// already gone (e.g. the kernel/network stack flushed it itself). The
	// desired end state - no route - already holds, so this isn't a real
	// error and shouldn't be logged as one.
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// setupProxyNeigh4 adds or removes a proxy ARP neighbor entry via netlink.
func setupProxyNeigh4(addr netip.Addr, ifindex int, add bool) error {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET,
		Flags:     unix.NTF_PROXY,
		IP:        net.IP(addr.AsSlice()),
	}

	if add {
		return netlink.NeighSet(n)
	}
	if err := netlink.NeighDel(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// seedNeighbor4 installs (or refreshes) a REACHABLE ARP cache entry mapping
// addr to mac on ifindex. Done right before delivering a DHCPACK so unicast
// delivery works immediately and the kernel never has to ARP-probe a client
// that has not finished configuring the address yet. The entry ages
// naturally afterwards (REACHABLE -> STALE -> probe -> FAILED), letting the
// sweep reap clients that disappeared.
func seedNeighbor4(addr netip.Addr, mac net.HardwareAddr, ifindex int) {
	n := &netlink.Neigh{
		LinkIndex:    ifindex,
		Family:       unix.AF_INET,
		State:        unix.NUD_REACHABLE,
		IP:           net.IP(addr.AsSlice()),
		HardwareAddr: mac,
	}
	if err := netlink.NeighSet(n); err != nil {
		Debugf("seed neigh %s on ifindex %d: %v", addr, ifindex, err)
	}
}

// deleteNeigh4 removes a real (non-proxy) ARP cache entry, e.g. after a
// client released its address. ESRCH/ENOENT just means it's already gone
// (raced with the kernel's own GC) and isn't worth logging.
func deleteNeigh4(addr netip.Addr, ifindex int) {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET,
		IP:        net.IP(addr.AsSlice()),
	}
	if err := netlink.NeighDel(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		Debugf("delete neigh %s on ifindex %d: %v", addr, ifindex, err)
	}
}