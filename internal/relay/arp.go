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

// Skip writes when re-applying settings that already match.
func setARPSysctl(path string, want byte) error {
	if cur, err := os.ReadFile(path); err == nil {
		if c := bytes.TrimSpace(cur); len(c) == 1 && c[0] == want {
			return nil
		}
	}
	return os.WriteFile(path, []byte{want, '\n'}, 0)
}

// arpSetup configures kernel proxy ARP for the given interface. Unlike the
// IPv6 side (which needs AF_PACKET capture sockets for NS relay), IPv4 proxy
// ARP is answered entirely by the kernel:
//   - on slave interfaces the "routed via a different interface" rule makes
//     the box answer client ARP requests for any upstream address (their
//     default gateway included) with the slave's own MAC;
//   - on master interfaces the NTF_PROXY entries installed per mirrored
//     client (see arpMirrorAddr) make the box answer upstream ARP requests
//     for relayed client addresses with the master's own MAC.
func arpSetup(iface *Interface, enable bool) error {
	want := byte('0')
	var delayErr error
	if enable && iface.ARP == ModeRelay {
		want = '1'
		if iface.Master {
			// Reply before an upstream DHCP server finishes checking
			// whether a downstream address is already in use.
			delayErr = setARPSysctl("/proc/sys/net/ipv4/neigh/"+iface.Ifname+"/proxy_delay", '0')
		}
	}
	return errors.Join(delayErr, setARPSysctl("/proc/sys/net/ipv4/conf/"+iface.Ifname+"/proxy_arp", want))
}

// arpMirrorAddr installs (or removes) a proxy-ARP entry on every other master
// interface, plus a /32 host route pointing back at the interface the address
// actually lives behind. The host route doubles as the "routed via a
// different interface" condition the kernel needs before it will answer a
// proxied ARP request at all.
func arpMirrorAddr(addr netip.Addr, iface *Interface, add bool) {
	for _, c := range interfaces {
		if c.Ifindex == 0 || c.Ifindex == iface.Ifindex || !c.Master || c.ARP != ModeRelay || (add && !c.Running) {
			continue
		}
		// Re-apply upstream ARP settings when an external reset had
		// no host route to remove and trigger handleRouteEvent.
		if add {
			if err := arpSetup(c, true); err != nil {
				Debugf("configure proxy ARP on %s: %v", c.Ifname, err)
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

func relayRouteAddress(route netlink.Route, ifindex int) (netip.Addr, bool) {
	if route.LinkIndex != ifindex || route.Priority != ourRouteMetric || route.Dst == nil ||
		route.Protocol != unix.RTPROT_STATIC || route.Scope != netlink.SCOPE_LINK || route.Table != unix.RT_TABLE_MAIN {
		return netip.Addr{}, false
	}
	if ones, bits := route.Dst.Mask.Size(); ones != 32 || bits != 32 {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(route.Dst.IP.To4())
}

func interfaceRouteAddresses(iface *Interface) []netip.Addr {
	if iface.Ifindex == 0 {
		return nil
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{LinkIndex: iface.Ifindex}, netlink.RT_FILTER_OIF)
	if err != nil {
		Warnf("list routes on %s: %v", iface.Ifname, err)
		return nil
	}
	var addrs []netip.Addr
	for _, route := range routes {
		if addr, ok := relayRouteAddress(route, iface.Ifindex); ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func removeInterfaceRoutes(iface *Interface) {
	for _, addr := range interfaceRouteAddresses(iface) {
		if err := setupRoute4(addr, 32, iface.Ifindex, ourRouteMetric, false); err != nil {
			Warnf("route %s/32 via %s: %v", addr, iface.Ifname, err)
		}
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
		Protocol:  unix.RTPROT_STATIC,
	}

	if add {
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
