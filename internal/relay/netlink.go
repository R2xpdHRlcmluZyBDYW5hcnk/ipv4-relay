package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// mirroredNeighKey tracks a downstream neighbor we have already mirrored
// (proxy-ARP entry + host route): we only want to touch the kernel on a real
// appear/disappear transition, not on every NUD reconfirmation cycle.
type mirroredNeighKey struct {
	addr    netip.Addr
	ifindex int
}

var mirroredNeighs = map[mirroredNeighKey]bool{}

// StartNetlinkMonitor subscribes to link/address/neighbor changes and
// forwards them to the Engine. It additionally subscribes to route changes:
// they are the event that lets the daemon self-heal after an external network
// manager - notably systemd-networkd driven by `netplan apply` - flushes the
// /32 host routes we install and, in the same reconfigure pass, resets
// net.ipv4.conf.<if>.proxy_arp back to 0. See handleRouteEvent.
func StartNetlinkMonitor(done <-chan struct{}) error {
	linkCh := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		return err
	}

	addrCh := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		return err
	}

	neighCh := make(chan netlink.NeighUpdate, 64)
	if err := netlink.NeighSubscribe(neighCh, done); err != nil {
		return err
	}

	// A flush (e.g. ManageForeignRoutes on `netplan apply`) deletes every one
	// of our host routes in a single burst, so give this channel plenty of
	// slack to avoid dropping updates before the reader drains them.
	routeCh := make(chan netlink.RouteUpdate, 256)
	if err := netlink.RouteSubscribe(routeCh, done); err != nil {
		return err
	}

	go func() {
		for {
			select {
			case u, ok := <-linkCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleLinkEvent(u) })
			case u, ok := <-addrCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleAddrEvent(u) })
			case u, ok := <-neighCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleNeighEvent(u) })
			case u, ok := <-routeCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleRouteEvent(u) })
			case <-done:
				return
			}
		}
	}()

	// Deferred to the first Reload() (see mirrorSweepOnce/scheduleMirrorSweep)
	// rather than started here: at this point config.json hasn't been loaded
	// yet, so staleClientSweepInterval would still be the built-in default even
	// if the config overrides it via global.stale_client_sweep_interval_seconds.
	mirrorSweepDone = done

	return nil
}

// mirrorSweepDone is StartNetlinkMonitor's done channel, stashed here so
// scheduleMirrorSweep (called from Reload, once config is loaded) can start
// the periodic sweep with the correct configured interval from the start.
var mirrorSweepDone <-chan struct{}

// mirrorSweepOnce ensures the periodic sweep is only ever started once,
// regardless of how many times Reload() runs (SIGHUP).
var mirrorSweepOnce sync.Once

// scheduleMirrorSweep starts the periodic mirror sweep on its first call
// (a no-op on subsequent calls), using whatever staleClientSweepInterval is
// in effect at that point. Must be called after loadConfigJSON so a
// configured global.stale_client_sweep_interval_seconds is already applied.
func scheduleMirrorSweep() {
	mirrorSweepOnce.Do(func() {
		if mirrorSweepDone != nil {
			startMirrorSweep(mirrorSweepDone)
		}
	})
}

// ourRouteMetric is the priority the daemon installs its persistent downstream
// /32 host routes with (see arpMirrorAddr). Filtering on this value keeps
// unrelated route churn from triggering reconciliation.
const ourRouteMetric = 1024

// staleClientSweepInterval is how often sweepFailedAndOrphans runs as a
// periodic backstop, in addition to the event-driven cleanup in
// handleNeighEvent/handleRouteEvent. It exists to catch things a purely
// event-driven mechanism can never notice: a real neighbor-cache entry that
// was already sitting in NUD_FAILED before this process's netlink
// subscription began (so no fresh event ever arrives for it), and an owned
// /32 host route / proxy-ARP entry whose neighbor-cache entry has since
// disappeared from the kernel entirely (not just gone FAILED) - either left
// over from a previous run of the daemon or from this one. It also actively
// probes any real neighbor entry currently sitting in NUD_STALE by asking
// the kernel to re-verify it (probeNeighbor sets NUD_PROBE, which makes the
// kernel itself send a real unicast ARP request and drive the NUD state
// machine from the reply, or lack of one) so a genuinely-dead host actually
// gets pushed to NUD_FAILED - a host that's simply gone silent otherwise
// stays STALE indefinitely and would never reach the FAILED reap above on
// its own.
//
// Overridable via global.stale_client_sweep_interval_seconds in config.json
// (see config.go's loadConfigJSON) - a package var rather than a const for
// that reason, default unchanged.
var staleClientSweepInterval = 300 * time.Second

// startMirrorSweep arranges for sweepFailedAndOrphans to run every
// staleClientSweepInterval until done is closed.
func startMirrorSweep(done <-chan struct{}) {
	var tick func()
	tick = func() {
		select {
		case <-done:
			return
		default:
		}
		Eng.Post(sweepFailedAndOrphans)
		time.AfterFunc(staleClientSweepInterval, tick)
	}
	time.AfterFunc(staleClientSweepInterval, tick)
}

// sweepFailedAndOrphans is the periodic backstop counterpart to
// handleNeighEvent/handleRouteEvent (see staleClientSweepInterval). It applies
// uniformly to every configured relay interface, master/WAN and slave/LAN
// alike. Runs on the Engine goroutine.
func sweepFailedAndOrphans() {
	for _, iface := range interfaces {
		if iface.ARP != ModeRelay {
			continue
		}
		sweepIfaceFailedAndOrphans(iface)
	}
}

// sweepIfaceFailedAndOrphans lists iface's current real (non-proxy) IPv4
// neighbor-cache entries and this daemon's own /32 host routes on iface,
// then (a) reaps any real neighbor entry already sitting in NUD_FAILED and
// (b) tears down (route + proxy-ARP mirror on every other master interface)
// any owned /32 route whose destination no longer has a matching real
// neighbor-cache entry at all - regardless of whether either was created by
// this process instance or a previous run.
func sweepIfaceFailedAndOrphans(iface *Interface) {
	link, err := netlink.LinkByIndex(iface.Ifindex)
	if err != nil {
		return
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET)
	if err != nil {
		Debugf("sweep: list neighbors on %s: %v", iface.Ifname, err)
		return
	}

	live := map[netip.Addr]bool{}

	for _, n := range neighs {
		if n.Flags&unix.NTF_PROXY != 0 {
			continue // our own proxy-ARP entries, not real neighbors
		}

		addr, ok := netip.AddrFromSlice(n.IP.To4())
		if !ok {
			continue
		}

		if addr.IsLoopback() || addr.IsMulticast() {
			continue
		}

		if n.State&unix.NUD_FAILED != 0 {
			key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
			if mirroredNeighs[key] {
				delete(mirroredNeighs, key)
				arpMirrorAddr(addr, iface, false)
			}
			deleteNeigh4(addr, iface.Ifindex)
			continue
		}

		if addr.IsLinkLocalUnicast() {
			continue
		}

		live[addr] = true

		if n.State&unix.NUD_STALE != 0 {
			// Actively probe: a genuinely-dead host would otherwise sit in
			// STALE forever (the kernel only re-confirms on next actual
			// traffic), so it would never reach NUD_FAILED for the reap
			// above to ever catch. The probe's outcome lands
			// asynchronously - a resulting FAILED transition is reaped on
			// the next sweep (or sooner via handleNeighEvent).
			probeNeighbor(addr, iface.Ifindex)
		}
	}

	routes, err := netlink.RouteList(link, unix.AF_INET)
	if err != nil {
		Debugf("sweep: list routes on %s: %v", iface.Ifname, err)
		return
	}

	for _, r := range routes {
		if r.LinkIndex != iface.Ifindex || r.Priority != ourRouteMetric || r.Dst == nil {
			continue
		}
		if ones, bits := r.Dst.Mask.Size(); bits != 32 || ones != 32 {
			continue
		}

		addr, ok := netip.AddrFromSlice(r.Dst.IP.To4())
		if !ok {
			continue
		}

		if live[addr] {
			continue
		}

		delete(mirroredNeighs, mirroredNeighKey{addr: addr, ifindex: iface.Ifindex})
		Noticef("Removing orphaned host route/proxy-ARP entry %s on %s (no matching neighbor left)", addr, iface.Ifname)
		arpMirrorAddr(addr, iface, false)
	}
}

// reconcileDebounce coalesces the burst of RTM_DELROUTE events an external
// flush produces into a single re-assertion pass, and lets the flush finish
// before we re-add so our routes stick instead of racing the deleter.
const reconcileDebounce = 2 * time.Second

// reconcileScheduled guards against stacking debounce timers. Only ever
// touched from the Engine goroutine.
var reconcileScheduled bool

// handleRouteEvent watches for deletion of the host routes the daemon owns.
// systemd-networkd (on `netplan apply`, with its default ManageForeignRoutes)
// flushes them and, in the same pass, resets proxy_arp to 0 - neither of which
// produces a link/address/neighbor event and neither of which the
// mirroredNeighs cache notices. The route deletion is the one observable
// signal, so a single (debounced) reconcile off it restores proxy_arp, the
// proxy-ARP entries and the host routes together. Runs on the Engine goroutine.
func handleRouteEvent(u netlink.RouteUpdate) {
	if u.Type != unix.RTM_DELROUTE || u.Priority != ourRouteMetric || u.Dst == nil {
		return
	}
	if ones, bits := u.Dst.Mask.Size(); bits != 32 || ones != 32 {
		return // only our /32 host routes
	}
	if iface := ifaceByIndex(u.LinkIndex); iface == nil || iface.ARP != ModeRelay {
		return
	}
	scheduleReconcile()
}

// scheduleReconcile arranges for exactly one reconcileKernelState() to run
// reconcileDebounce from now, collapsing a flush's event burst into a single
// pass. Runs on (and only touches state from) the Engine goroutine.
func scheduleReconcile() {
	if reconcileScheduled {
		return
	}
	reconcileScheduled = true
	time.AfterFunc(reconcileDebounce, func() {
		Eng.Post(func() {
			reconcileScheduled = false
			reconcileKernelState()
		})
	})
}

// reconcileKernelState re-applies the proxy_arp sysctl, proxy-ARP neighbor
// entries and host routes the daemon is responsible for. Every underlying
// operation (sysctl write, NeighSet, RouteReplace) is idempotent, so on the
// steady-state happy path this is a cheap no-op; it only actually changes
// anything when something external removed our state. Runs on the Engine
// goroutine.
func reconcileKernelState() {
	for _, iface := range interfaces {
		if iface.ARP != ModeRelay {
			continue
		}
		if err := setProxyARP(iface.Ifname, true); err != nil {
			Debugf("reconcile proxy_arp on %s: %v", iface.Ifname, err)
		}
	}

	// Re-assert the mirror for every downstream host we have learned.
	for key := range mirroredNeighs {
		iface := ifaceByIndex(key.ifindex)
		if iface == nil {
			continue
		}
		arpMirrorAddr(key.addr, iface, true)
	}
}

// handleLinkEvent reacts to a real carrier up/down transition (IFF_RUNNING
// toggling) on a tracked interface by (re)enabling or tearing down its relay services.
func handleLinkEvent(u netlink.LinkUpdate) {
	ifname := u.Attrs().Name

	iface := ifaceByIfname(ifname)
	if iface == nil {
		return
	}

	if u.Header.Type == unix.RTM_DELLINK {
		if iface.Ifindex != int(u.Index) {
			return
		}

		disableServices(iface)
		clearMirroredState(iface)
		iface.Ifindex = 0
		iface.Running = false
		iface.Addr4 = nil
		return
	}

	nowRunning := u.IfInfomsg.Flags&unix.IFF_RUNNING != 0

	if iface.Ifindex == int(u.Index) {
		wasRunning := iface.Running
		iface.Running = nowRunning

		if wasRunning != nowRunning {
			if nowRunning {
				refreshInterfaceAddresses(iface)
			}
			reloadServices(iface)
		}
		return
	}

	// A same-name interface can come back with a new ifindex. Sockets and
	// mirrored-neighbor bookkeeping all refer to the old index and must be
	// replaced as one lifecycle change.
	disableServices(iface)
	clearMirroredState(iface)
	iface.Ifindex = int(u.Index)
	iface.Running = nowRunning
	refreshInterfaceAddresses(iface)
	reloadServices(iface)
}

// handleAddrEvent refreshes the cached address list for the interface. The
// relayed-giaddr selection (relayLinkAddress4) reads that cache, so a master
// interface that only gets its IPv4 address after we started still picks it
// up without a reload.
func handleAddrEvent(u netlink.AddrUpdate) {
	if u.LinkAddress.IP.To4() == nil {
		return // IPv6, irrelevant to this daemon
	}

	iface := ifaceByIndex(u.LinkIndex)
	if iface == nil {
		return
	}

	refreshInterfaceAddresses(iface)
}

func clearMirroredState(iface *Interface) {
	for key := range mirroredNeighs {
		if key.ifindex != iface.Ifindex {
			continue
		}
		arpMirrorAddr(key.addr, iface, false)
		delete(mirroredNeighs, key)
	}
}

// handleNeighEvent handles neighbor resolution events: once the kernel
// resolves a downstream host's address (NUD_REACHABLE/STALE/DELAY/PROBE/
// PERMANENT/NOARP), mirror it into proxy-ARP + a host route; only an explicit
// NUD_FAILED reaps that mirror again. A plain deletion (idle STALE GC)
// intentionally leaves the mirror in place so idle-but-present hosts are not
// blackholed.
//
// A NUD_FAILED entry is also reaped from the kernel's neighbor cache
// unconditionally, not just when it was mirrored: left alone, failed ARP
// entries otherwise linger in `ip neigh show`.
func handleNeighEvent(u netlink.NeighUpdate) {
	if u.Type != unix.RTM_NEWNEIGH {
		return
	}

	iface := ifaceByIndex(u.LinkIndex)
	if iface == nil || iface.ARP != ModeRelay {
		return
	}

	addr, ok := netip.AddrFromSlice(u.IP.To4())
	if !ok {
		return // not IPv4
	}

	if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return
	}

	key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
	mirrored := mirroredNeighs[key]

	const resolvedMask = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY |
		unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP

	resolved := u.State&resolvedMask != 0
	failed := u.State&unix.NUD_FAILED != 0

	if resolved && !mirrored {
		mirroredNeighs[key] = true
		arpMirrorAddr(addr, iface, true)
	} else if failed {
		if mirrored {
			delete(mirroredNeighs, key)
			arpMirrorAddr(addr, iface, false)
		}
		deleteNeigh4(addr, iface.Ifindex)
	}
}

// probeNeighbor asks the kernel to re-verify a real (non-proxy) neighbor-
// cache entry by setting it to NUD_PROBE: the kernel itself then sends a
// real unicast ARP request and drives the entry to REACHABLE (reply) or
// FAILED (no reply after retries) accordingly - see
// sweepIfaceFailedAndOrphans. ESRCH/ENOENT just means the entry is already
// gone (raced with the kernel's own GC) and isn't worth logging.
func probeNeighbor(addr netip.Addr, ifindex int) {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET,
		State:     unix.NUD_PROBE,
		IP:        net.IP(addr.AsSlice()),
	}
	if err := netlink.NeighSet(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		Debugf("probe neigh %s on ifindex %d: %v", addr, ifindex, err)
	}
}