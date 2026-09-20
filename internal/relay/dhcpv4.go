package relay

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// RFC 2131 / RFC 1542 BOOTP/DHCPv4 wire layout: the fixed header is 236
// bytes, followed by the 4-byte magic cookie and the options area.
const (
	bootpFixedLen  = 236
	bootpSnameOff  = 44
	bootpSnameLen  = 64
	bootpFileOff   = 108
	bootpFileLen   = 128
	dhcpCookieOff  = 236
	dhcpOptionsOff = 240

	dhcpv4ServerPort = 67
	dhcpv4ClientPort = 68

	bootpRequest = 1
	bootpReply   = 2

	bootpBroadcastFlag = 0x8000 // flags field, big endian at offset 10

	dhcpMaxHops    = 16
	dhcpMaxPktSize = 1400 // guard for appending option 82 without risking MTU

	dhcpOptPad       = 0
	dhcpOptEnd       = 255
	dhcpOptMsgType   = 53
	dhcpOptOverload  = 52 // RFC 2132 section 9.3, sname/file option overloading
	dhcpOptRequested = 50
	dhcpOptAgentInfo = 82 // RFC 3046 relay agent information

	agentSubOptCircuitID = 1

	dhcpMsgDiscover = 1
	dhcpMsgOffer    = 2
	dhcpMsgRequest  = 3
	dhcpMsgDecline  = 4
	dhcpMsgAck      = 5
	dhcpMsgNak      = 6
	dhcpMsgRelease  = 7
	dhcpMsgInform   = 8
)

var dhcpMagicCookie = []byte{99, 130, 83, 99}

func dhcpMsgTypeName(t int) string {
	switch t {
	case dhcpMsgDiscover:
		return "discover"
	case dhcpMsgOffer:
		return "offer"
	case dhcpMsgRequest:
		return "request"
	case dhcpMsgDecline:
		return "decline"
	case dhcpMsgAck:
		return "ack"
	case dhcpMsgNak:
		return "nak"
	case dhcpMsgRelease:
		return "release"
	case dhcpMsgInform:
		return "inform"
	default:
		return "unknown"
	}
}

type dhcpSock struct {
	fd    int
	iface *Interface
	done  chan struct{}
}

func openDHCPSocket(iface *Interface, port int) (*dhcpSock, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		Errorf("socket(AF_INET) for dhcpv4 relay on %s:%d: %v", iface.Ifname, port, err)
		return nil, err
	}

	ok := false
	defer func() {
		if !ok {
			closeFD(fd)
		}
	}()

	if err := bindToDevice(fd, iface.Ifname); err != nil {
		Errorf("SO_BINDTODEVICE(%s): %v", iface.Ifname, err)
		return nil, err
	}
	if err := setsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		Errorf("SO_REUSEADDR: %v", err)
		return nil, err
	}
	if err := setsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		Errorf("SO_REUSEPORT: %v", err)
		return nil, err
	}
	if err := setsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
		Errorf("SO_BROADCAST: %v", err)
		return nil, err
	}

	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port}); err != nil {
		Errorf("bind(:%d) on %s: %v", port, iface.Ifname, err)
		return nil, err
	}

	ds := &dhcpSock{fd: fd, iface: iface, done: make(chan struct{})}
	ok = true
	go dhcpReadLoop(ds)
	return ds, nil
}

// dhcpv4Setup opens (or tears down) UDP sockets bound to the given
// interface. Slave sockets receive client broadcasts (port 67); master sockets
// receive server replies (port 67 for RFC 2131 unicast/broadcast, port 68 for
// non-compliant upstream servers like ISP modems broadcasting replies to the client port).
func dhcpv4Setup(iface *Interface, enable bool) error {
	enable = enable && iface.DHCPv4 != ModeDisabled

	if len(iface.dhcp) > 0 {
		for _, ds := range iface.dhcp {
			close(ds.done)
			closeFD(ds.fd)
		}
		iface.dhcp = nil
	}

	if !enable {
		return nil
	}

	ds67, err := openDHCPSocket(iface, dhcpv4ServerPort)
	if err != nil {
		return err
	}
	iface.dhcp = append(iface.dhcp, ds67)

	if iface.Master {
		ds68, err := openDHCPSocket(iface, dhcpv4ClientPort)
		if err != nil {
			Warnf("Failed to bind port 68 on master %s (broadcast server replies may be missed): %v", iface.Ifname, err)
		} else {
			iface.dhcp = append(iface.dhcp, ds68)
		}
	}

	return nil
}

func dhcpReadLoop(ds *dhcpSock) {
	buf := make([]byte, 2048)

	for {
		select {
		case <-ds.done:
			return
		default:
		}

		n, from, err := unix.Recvfrom(ds.fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			select {
			case <-ds.done:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}

		var src netip.Addr
		if sa4, ok := from.(*unix.SockaddrInet4); ok {
			src = netip.AddrFrom4(sa4.Addr)
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		Eng.Post(func() { handleDHCPv4(ds, src, data) })
	}
}

func ifaceHasDHCPSock(iface *Interface, ds *dhcpSock) bool {
	for _, s := range iface.dhcp {
		if s == ds {
			return true
		}
	}
	return false
}

// handleDHCPv4 processes incoming DHCPv4 packets: BOOTREQUESTs are only ever
// relayed when they arrive on a slave interface (a BOOTREQUEST seen on a
// master is some other network's client - or our own relayed broadcast
// looping back - and is never ours to relay), BOOTREPLYs only on masters.
func handleDHCPv4(ds *dhcpSock, src netip.Addr, data []byte) {
	iface := ds.iface
	if !ifaceHasDHCPSock(iface, ds) || iface.DHCPv4 != ModeRelay {
		return
	}

	if len(data) < dhcpOptionsOff {
		return
	}
	if data[1] != 1 || data[2] != 6 { // htype ethernet, hlen 6
		return
	}
	if !bytes.Equal(data[dhcpCookieOff:dhcpOptionsOff], dhcpMagicCookie) {
		return
	}

	switch data[0] {
	case bootpRequest:
		if !iface.Master {
			relayClientRequest(data, iface)
		}
	case bootpReply:
		if iface.Master {
			relayServerResponse(src, data, iface)
		}
	}
}

// dhcpOption holds one parsed DHCP option: code and payload.
type dhcpOption struct {
	code byte
	data []byte
}

// parseDHCPOptions collects the packet's DHCP options, honoring option
// overloading (RFC 2132 section 9.3): when the main options area carries
// option 52, the sname/file header fields hold additional option areas that
// are parsed after the main area, file first then sname (the order common
// client implementations use). The main area is parsed strictly - a malformed
// or unterminated one means the packet is not DHCP. A header field claimed to
// be overloaded that fails to parse is skipped instead of invalidating the
// packet: the main area is already well-formed and the overload hint may
// simply be wrong.
func parseDHCPOptions(data []byte) []dhcpOption {
	out := parseOptionArea(data[dhcpOptionsOff:])
	if out == nil {
		return nil
	}

	ov, ok := dhcpOptionByte(out, dhcpOptOverload)
	if !ok {
		return out
	}

	appendField := func(off, size int) {
		if area := parseOptionArea(data[off : off+size]); area != nil {
			out = append(out, area...)
		}
	}
	switch ov {
	case 1: // file holds options
		appendField(bootpFileOff, bootpFileLen)
	case 2: // sname holds options
		appendField(bootpSnameOff, bootpSnameLen)
	case 3: // both, file first
		appendField(bootpFileOff, bootpFileLen)
		appendField(bootpSnameOff, bootpSnameLen)
	}
	return out
}

// parseOptionArea walks one options area (the main options area or an
// overloaded header field), tolerating pad bytes. Returns nil if the area is
// malformed or runs off the end without an End option.
func parseOptionArea(area []byte) []dhcpOption {
	var out []dhcpOption

	off := 0
	for {
		if off >= len(area) {
			return nil // ran off the end without an End option
		}
		code := area[off]
		if code == dhcpOptEnd {
			return out
		}
		if code == dhcpOptPad {
			off++
			continue
		}
		if off+2 > len(area) {
			return nil
		}
		l := int(area[off+1])
		if off+2+l > len(area) {
			return nil
		}
		out = append(out, dhcpOption{code: code, data: area[off+2 : off+2+l]})
		off += 2 + l
	}
}

func dhcpOptionByte(opts []dhcpOption, code byte) (int, bool) {
	for _, o := range opts {
		if o.code == code && len(o.data) == 1 {
			return int(o.data[0]), true
		}
	}
	return 0, false
}

// parseCircuitID extracts our RFC 3046 circuit-id sub-option (a 4-byte
// little-endian ifindex) from an option-82 payload echoed back by the server.
func parseCircuitID(agentInfo []byte) (int, bool) {
	off := 0
	for off+2 <= len(agentInfo) {
		sub := agentInfo[off]
		l := int(agentInfo[off+1])
		if off+2+l > len(agentInfo) {
			break
		}
		if sub == agentSubOptCircuitID && l == 4 {
			return int(int32(binary.LittleEndian.Uint32(agentInfo[off+2 : off+6]))), true
		}
		off += 2 + l
	}
	return 0, false
}

// insertAgentInfo returns a copy of the client packet with an RFC 3046
// option 82 (circuit-id = the slave interface's ifindex) inserted just before
// the End option, so a relayed reply can be routed back to the right slave.
// If the packet already carries option 82 (another relay downstream of us)
// the packet is relayed unmodified - the reply then falls back to being
// broadcast on all slaves.
func insertAgentInfo(data []byte, ifindex int) ([]byte, bool) {
	off := dhcpOptionsOff
	for {
		if off >= len(data) {
			return nil, false
		}
		code := data[off]
		if code == dhcpOptEnd {
			break
		}
		if code == dhcpOptPad {
			off++
			continue
		}
		if code == dhcpOptAgentInfo {
			return data, true // already relayed: keep as-is
		}
		if off+2 > len(data) {
			return nil, false
		}
		off += 2 + int(data[off+1])
		if off > len(data) {
			return nil, false
		}
	}

	if len(data)+8 > dhcpMaxPktSize {
		return nil, false
	}

	out := make([]byte, 0, len(data)+8)
	out = append(out, data[:off]...)
	out = append(out, dhcpOptAgentInfo, 6, agentSubOptCircuitID, 4)
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], uint32(ifindex))
	out = append(out, idx[:]...)
	out = append(out, data[off:]...)
	return out, true
}

// stripAgentInfo returns a copy of the server reply with every option 82
// removed (clients never asked for it and some choke on it), preserving the
// End option and any trailing padding. Only the main options area is scanned:
// a server echoing option 82 into an overloaded sname/file field does not
// happen in practice, and rewriting fixed-size header fields is not worth the
// byte surgery.
func stripAgentInfo(data []byte) []byte {
	if len(data) < dhcpOptionsOff {
		return data
	}

	out := make([]byte, 0, len(data))
	out = append(out, data[:dhcpOptionsOff]...)

	off := dhcpOptionsOff
	for off < len(data) {
		code := data[off]
		if code == dhcpOptEnd {
			out = append(out, data[off:]...)
			return out
		}
		if code == dhcpOptPad {
			out = append(out, code)
			off++
			continue
		}
		if off+2 > len(data) {
			break
		}
		l := int(data[off+1])
		if off+2+l > len(data) {
			break
		}
		if code != dhcpOptAgentInfo {
			out = append(out, data[off:off+2+l]...)
		}
		off += 2 + l
	}

	// Malformed tail: make sure the result is at least terminated.
	out = append(out, dhcpOptEnd)
	return out
}

// relayClientRequest relays a client BOOTREQUEST received on a slave
// interface out every master interface. DHCPv4 is broadcast-based, so the
// relay is plug-and-play: the request (giaddr stamped with the master's own
// address, per RFC 1542) is re-broadcast upstream, and the server unicasts
// its reply back to that giaddr.
func relayClientRequest(data []byte, iface *Interface) {
	if data[3] >= dhcpMaxHops {
		return
	}

	opts := parseDHCPOptions(data)
	msgType, _ := dhcpOptionByte(opts, dhcpOptMsgType)

	Debugf("Got a DHCPv4-%s on %s", dhcpMsgTypeName(msgType), iface.Name)

	// A client releasing/declining an address lets us drop the proxy-ARP
	// mirror and the /32 host route immediately instead of waiting for the
	// periodic sweep to notice the gone address.
	switch msgType {
	case dhcpMsgRelease:
		if ci, ok := netip.AddrFromSlice(data[12:16]); ok && ci.Is4() && !ci.IsUnspecified() {
			unmirrorClient(ci, iface)
		}
	case dhcpMsgDecline:
		for _, o := range opts {
			if o.code == dhcpOptRequested && len(o.data) == 4 {
				if a, ok := netip.AddrFromSlice(o.data); ok {
					unmirrorClient(a, iface)
				}
			}
		}
	}

	// Option 82 return routing is an optimization, not a prerequisite: if it
	// cannot be inserted (packet too large to append it safely, malformed
	// options area), relay the packet unmodified and let replies fall back to
	// being broadcast on every slave - that beats not relaying at all.
	out82, have82 := insertAgentInfo(data, iface.Ifindex)
	if !have82 {
		Warnf("Cannot insert option 82 into DHCPv4 packet on %s, relaying without it", iface.Name)
	}

	for _, c := range interfaces {
		if !c.Master || c.DHCPv4 != ModeRelay || len(c.dhcp) == 0 {
			continue
		}

		giaddr, ok := relayLinkAddress4(c)
		if !ok {
			Debugf("No IPv4 address on %s yet, skipping relay", c.Name)
			continue
		}

		out := out82
		if !have82 {
			out = data
		}

		// Per-master copy: hops and giaddr are ours to set.
		out = append([]byte(nil), out...)
		out[3]++ // hops
		if bytes.Equal(out[24:28], []byte{0, 0, 0, 0}) {
			copy(out[24:28], giaddr.AsSlice()) // giaddr
		}
		// Force the broadcast flag on the relayed copy. Some servers (ISP
		// modems observed in the field) silently drop relayed requests with
		// the flag clear: instead of returning the reply via giaddr they try
		// to deliver it to the client directly, ARP for the offered address
		// on their own segment, get no answer and drop the reply - iOS/macOS
		// clients habitually clear the flag and never lease through them.
		// Clients must accept broadcast replies per RFC 2131 section 4.1, so
		// this is safe against compliant servers; it only costs us the
		// unicast-ACK delivery path when the server echoes the flag.
		out[10] |= byte(bootpBroadcastFlag >> 8)

		Debugf("Relaying DHCPv4-%s (giaddr %s) to broadcast on %s", dhcpMsgTypeName(msgType), giaddr, c.Name)
		sendDHCPv4(c, broadcastAddr, dhcpv4ServerPort, out)
	}
}

// relayServerResponse relays a server BOOTREPLY received on a master
// interface to the slave the circuit-id option names (falling back to all
// slaves when the server did not echo option 82). OFFER/NAK are always
// broadcast on the slave; an ACK additionally seeds the client's ARP entry
// and installs the proxy-ARP mirror + /32 host route before the packet is
// delivered, so the address is fully reachable the moment the client
// configures it.
func relayServerResponse(src netip.Addr, data []byte, master *Interface) {
	opts := parseDHCPOptions(data)
	if opts == nil {
		return
	}

	msgType, _ := dhcpOptionByte(opts, dhcpOptMsgType)

	Debugf("Got a DHCPv4-%s from %s on %s", dhcpMsgTypeName(msgType), src, master.Name)

	var (
		slave     *Interface
		haveSlave bool
	)
	for _, o := range opts {
		if o.code == dhcpOptAgentInfo {
			if idx, ok := parseCircuitID(o.data); ok {
				if i := ifaceByIndex(idx); i != nil && !i.Master {
					slave, haveSlave = i, true
				}
			}
		}
	}

	payload := stripAgentInfo(data)

	targets := make([]*Interface, 0, 1)
	if haveSlave {
		targets = append(targets, slave)
	} else {
		for _, i := range interfaces {
			if !i.Master && i.DHCPv4 == ModeRelay && len(i.dhcp) > 0 {
				targets = append(targets, i)
			}
		}
	}

	yiaddr, hasYi := netip.AddrFromSlice(data[16:20])
	if hasYi && (!yiaddr.Is4() || yiaddr.IsUnspecified() || yiaddr.IsMulticast() || yiaddr.IsLoopback() || yiaddr.IsLinkLocalUnicast()) {
		hasYi = false
	}
	flags := binary.BigEndian.Uint16(data[10:12])

	for _, t := range targets {
		if msgType == dhcpMsgAck && hasYi {
			var mac [6]byte
			copy(mac[:], data[28:34])
			Infof("DHCPv4-ack: %s assigned to %02x:%02x:%02x:%02x:%02x:%02x on %s",
				yiaddr, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], t.Name)
			key := mirroredNeighKey{addr: yiaddr, ifindex: t.Ifindex}
			if !mirroredNeighs[key] {
				mirroredNeighs[key] = true
				arpMirrorAddr(yiaddr, t, true)
			}
			seedNeighbor4(yiaddr, net.HardwareAddr(mac[:]), t.Ifindex)
		}

		dest := broadcastAddr
		if flags&bootpBroadcastFlag == 0 && msgType == dhcpMsgAck && hasYi {
			dest = yiaddr // unicast delivery, ARP entry seeded above
		}
		Debugf("Sending DHCPv4-%s to %s on %s", dhcpMsgTypeName(msgType), dest, t.Name)
		sendDHCPv4(t, dest, dhcpv4ClientPort, payload)
	}
}

// unmirrorClient tears down the proxy-ARP mirror, host route and ARP cache
// entry for an address a client just gave up. Only touches state that is
// actually mirrored, so it is safe to call for any address.
func unmirrorClient(addr netip.Addr, iface *Interface) {
	key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
	if !mirroredNeighs[key] {
		return
	}
	delete(mirroredNeighs, key)
	Infof("Client on %s gave up %s, removing mirror", iface.Name, addr)
	arpMirrorAddr(addr, iface, false)
	deleteNeigh4(addr, iface.Ifindex)
}

// sendDHCPv4 sends payload out iface's DHCPv4 socket toward dest:port.
func sendDHCPv4(iface *Interface, dest netip.Addr, port int, payload []byte) {
	if len(iface.dhcp) == 0 {
		return
	}

	if err := unix.Sendto(iface.dhcp[0].fd, payload, 0, sockaddrIn4(dest, port)); err != nil {
		Errorf("Failed to send DHCPv4 to %s@%s: %v", dest, iface.Ifname, err)
	} else {
		Debugf("Sent %d bytes DHCPv4 to %s:%d@%s", len(payload), dest, port, iface.Ifname)
	}
}