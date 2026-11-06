package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
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
	dhcpOptMask      = 1
	dhcpOptRouter    = 3
	dhcpOptMsgType   = 53
	dhcpOptOverload  = 52 // RFC 2132 section 9.3, sname/file option overloading
	dhcpOptRequested = 50
	dhcpOptServerID  = 54
	dhcpOptClientID  = 61
	dhcpOptAgentInfo = 82 // RFC 3046 relay agent information
	dhcpOptRoutes    = 121

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

var (
	dhcpMagicCookie = []byte{99, 130, 83, 99}
	broadcastAddr   = netip.MustParseAddr("255.255.255.255")
)

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
	conn  *net.UDPConn
	iface *Interface
	done  chan struct{}
}

func openDHCPSocket(iface *Interface, port int) (*dhcpSock, error) {
	lc := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		var socketErr error
		if err := conn.Control(func(fd uintptr) {
			socketErr = configureDHCPSocket(int(fd), iface.Ifname)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	conn, err := lc.ListenPacket(context.Background(), "udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("DHCPv4 socket on %s:%d: %w", iface.Ifname, port, err)
	}

	ds := &dhcpSock{conn: conn.(*net.UDPConn), iface: iface, done: make(chan struct{})}
	go dhcpReadLoop(ds)
	return ds, nil
}

func configureDHCPSocket(fd int, ifname string) error {
	if err := unix.BindToDevice(fd, ifname); err != nil {
		return err
	}
	for _, opt := range []int{unix.SO_REUSEADDR, unix.SO_REUSEPORT, unix.SO_BROADCAST} {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, 1); err != nil {
			return err
		}
	}
	return nil
}

// The upstream also listens on port 68 for servers that broadcast replies to
// the client port. Port 67 is the required socket for either role.
func startDHCP(iface *Interface) error {
	ds67, err := openDHCPSocket(iface, dhcpv4ServerPort)
	if err != nil {
		return err
	}
	iface.dhcp = append(iface.dhcp, ds67)

	if iface.Master {
		startUpstreamClientPort(iface)
	}

	return nil
}

func startUpstreamClientPort(iface *Interface) {
	ds, err := openDHCPSocket(iface, dhcpv4ClientPort)
	if err != nil {
		Warnf("Failed to bind port 68 on master %s (broadcast server replies may be missed): %v", iface.Ifname, err)
		return
	}
	iface.dhcp = append(iface.dhcp, ds)
}

func stopDHCP(iface *Interface) {
	for _, ds := range iface.dhcp {
		close(ds.done)
		_ = ds.conn.Close()
	}
	iface.dhcp = nil
}

func dhcpReadLoop(ds *dhcpSock) {
	buf := make([]byte, 2048)

	for {
		n, src, err := ds.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
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

		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case Eng.events <- func() { handleDHCPv4(ds, src, data) }:
		case <-ds.done:
			return
		}
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
func handleDHCPv4(ds *dhcpSock, src netip.AddrPort, data []byte) {
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
		if !iface.Master && src.Port() == dhcpv4ClientPort {
			relayClientRequest(data, iface)
		}
	case bootpReply:
		if iface.Master && src.Port() == dhcpv4ServerPort && src.Addr().Unmap().IsGlobalUnicast() {
			relayServerResponse(src.Addr().Unmap(), data, iface)
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
// The caller validates any client-supplied Option 82 before insertion.
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
	if data[3] >= dhcpMaxHops || !netip.AddrFrom4([4]byte(data[24:28])).IsUnspecified() {
		return
	}

	opts := parseDHCPOptions(data)
	msgType, ok := dhcpOptionByte(opts, dhcpOptMsgType)
	if !ok {
		return
	}
	for _, opt := range opts {
		if opt.code == dhcpOptAgentInfo {
			return // RFC 3046: clients on an untrusted link cannot supply Option 82.
		}
	}

	Debugf("Got a DHCPv4-%s on %s", dhcpMsgTypeName(msgType), iface.Name)

	client := dhcpClientFrom(data, opts)
	ciaddr := netip.AddrFrom4([4]byte(data[12:16]))
	address := dhcpOptionAddr(opts, dhcpOptRequested)
	if ciaddr.IsGlobalUnicast() {
		address = ciaddr
	}
	var relinquished netip.Addr
	switch msgType {
	case dhcpMsgDiscover, dhcpMsgRequest, dhcpMsgInform:
	case dhcpMsgRelease:
		relinquished = ciaddr
	case dhcpMsgDecline:
		relinquished = dhcpOptionAddr(opts, dhcpOptRequested)
	default:
		return
	}
	if relinquished.IsValid() && !unmirrorClient(relinquished, iface, client) {
		return
	}

	// If there is no room for Option 82, transaction state still identifies
	// the downstream interface when the reply comes back.
	out82, have82 := insertAgentInfo(data, iface.Ifindex)
	if !have82 {
		Warnf("Cannot insert option 82 into DHCPv4 packet on %s, relaying without it", iface.Name)
		out82 = data
	}

	now := time.Now()
	expectReply := msgType == dhcpMsgDiscover || msgType == dhcpMsgRequest || msgType == dhcpMsgInform
	for _, c := range interfaces {
		if !c.Master || c.DHCPv4 != ModeRelay || len(c.dhcp) == 0 {
			continue
		}

		giaddr, ok := relayLinkAddress4(c)
		if !ok {
			Debugf("No IPv4 address on %s yet, skipping relay", c.Name)
			continue
		}

		key := dhcpTransactionFor(data, c)
		if expectReply && !canTrackDHCP(key, iface, now) {
			continue
		}

		// Per-master copy: hops and giaddr are ours to set.
		out := append([]byte(nil), out82...)
		out[3]++ // hops
		copy(out[24:28], giaddr.AsSlice())
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
		if sendDHCPv4(c, broadcastAddr, dhcpv4ServerPort, out) && expectReply {
			dhcpRequests[key] = pendingDHCP{
				slave: iface, client: client, kind: msgType, giaddr: giaddr,
				server: dhcpOptionAddr(opts, dhcpOptServerID), address: address,
				expires: now.Add(dhcpRequestLifetime),
			}
		}
	}
}

// rewriteGateway changes the preferred router only when the lease makes it
// reachable on-link. Preserve the server's options when classless routes
// take precedence or the client subnet cannot be established.
func rewriteGateway(data []byte, gw netip.Addr) bool {
	if len(data) < dhcpOptionsOff || !gw.Is4() || !gw.IsGlobalUnicast() {
		return false
	}
	client := netip.AddrFrom4([4]byte(data[16:20]))
	if client.IsUnspecified() {
		client = netip.AddrFrom4([4]byte(data[12:16]))
	}
	if !client.IsGlobalUnicast() || client == gw {
		return false
	}
	var mask, routers []byte
	for _, opt := range parseDHCPOptions(data) {
		switch opt.code {
		case dhcpOptRoutes:
			return false
		case dhcpOptMask:
			mask = opt.data
		case dhcpOptRouter:
			if routers == nil {
				routers = opt.data
			}
		}
	}
	ones, bits := net.IPMask(mask).Size()
	if bits != 32 || ones == 0 || len(routers) < 4 || len(routers)%4 != 0 {
		return false
	}
	prefix := netip.PrefixFrom(client, ones).Masked()
	if !prefix.Contains(gw) {
		return false
	}
	if ones < 31 {
		broadcast := binary.BigEndian.Uint32(prefix.Addr().AsSlice()) | ^binary.BigEndian.Uint32(mask)
		if gw == prefix.Addr() || binary.BigEndian.Uint32(gw.AsSlice()) == broadcast {
			return false
		}
	}
	copy(routers[:4], gw.AsSlice())
	return true
}

// relayServerResponse relays a server BOOTREPLY received on a master
// interface to the slave recorded when the request was sent. OFFER/NAK are
// broadcast on the slave; an ACK additionally seeds the client's ARP entry
// and installs the proxy-ARP mirror + /32 host route before the packet is
// delivered, so the address is fully reachable the moment the client
// configures it.
func relayServerResponse(src netip.Addr, data []byte, master *Interface) {
	opts := parseDHCPOptions(data)
	if opts == nil {
		return
	}

	msgType, ok := dhcpOptionByte(opts, dhcpOptMsgType)
	if !ok {
		return
	}
	key := dhcpTransactionFor(data, master)
	request, ok := matchDHCPReply(key, data, opts, msgType, time.Now())
	if !ok {
		return
	}

	Debugf("Got a DHCPv4-%s from %s on %s", dhcpMsgTypeName(msgType), src, master.Name)

	slave := request.slave
	payload := stripAgentInfo(data)
	if gw, ok := relayLinkAddress4(slave); ok && rewriteGateway(payload, gw) {
		Debugf("DHCPv4-%s gateway rewritten to %s on %s", dhcpMsgTypeName(msgType), gw, slave.Name)
	}

	yiaddr := netip.AddrFrom4([4]byte(data[16:20]))
	dest := broadcastAddr
	if msgType == dhcpMsgAck && request.kind == dhcpMsgRequest && yiaddr.IsGlobalUnicast() {
		mac := net.HardwareAddr(request.client.mac[:])
		Infof("DHCPv4-ack: %s assigned to %s on %s", yiaddr, mac, slave.Name)
		neighbor := mirroredNeighKey{addr: yiaddr, ifindex: slave.Ifindex}
		if !mirroredNeighs[neighbor] {
			mirroredNeighs[neighbor] = true
			arpMirrorAddr(yiaddr, slave, true)
		}
		dhcpLeases[neighbor] = request.client
		seedNeighbor4(yiaddr, mac, slave.Ifindex)
		if binary.BigEndian.Uint16(data[10:12])&bootpBroadcastFlag == 0 {
			dest = yiaddr
		}
	}
	Debugf("Sending DHCPv4-%s to %s on %s", dhcpMsgTypeName(msgType), dest, slave.Name)
	if sendDHCPv4(slave, dest, dhcpv4ClientPort, payload) && msgType != dhcpMsgOffer {
		for _, upstream := range interfaces {
			key.master = upstream
			if other := dhcpRequests[key]; other.slave == slave {
				delete(dhcpRequests, key)
			}
		}
	}
}

// unmirrorClient accepts a release only from the recorded owner. Unknown
// leases can be forwarded upstream without deleting any local state.
func unmirrorClient(addr netip.Addr, iface *Interface, client dhcpClient) bool {
	key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
	owner, ok := dhcpLeases[key]
	if !ok {
		return true
	}
	if owner != client {
		return false
	}
	delete(dhcpLeases, key)
	delete(mirroredNeighs, key)
	Infof("Client on %s gave up %s, removing mirror", iface.Name, addr)
	arpMirrorAddr(addr, iface, false)
	deleteNeigh4(addr, iface.Ifindex)
	return true
}

// sendDHCPv4 sends payload out iface's DHCPv4 socket toward dest:port.
func sendDHCPv4(iface *Interface, dest netip.Addr, port int, payload []byte) bool {
	if len(iface.dhcp) == 0 {
		return false
	}

	if _, err := iface.dhcp[0].conn.WriteToUDPAddrPort(payload, netip.AddrPortFrom(dest, uint16(port))); err != nil {
		Errorf("Failed to send DHCPv4 to %s@%s: %v", dest, iface.Ifname, err)
		return false
	}
	Debugf("Sent %d bytes DHCPv4 to %s:%d@%s", len(payload), dest, port, iface.Ifname)
	return true
}
