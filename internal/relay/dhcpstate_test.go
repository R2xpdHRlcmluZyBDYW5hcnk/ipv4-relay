package relay

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMatchDHCPReply(t *testing.T) {
	now := time.Now()
	master := &Interface{Ifindex: 2}
	slave := &Interface{Ifindex: 3, dhcp: []*dhcpSock{{}}}
	server := netip.MustParseAddr("192.0.2.1")
	lease := netip.MustParseAddr("192.0.2.42")
	base := buildDHCP(optBytes(dhcpOptMsgType, dhcpMsgAck), optBytes(dhcpOptServerID, server.AsSlice()...))
	base[0] = bootpReply
	base[4], base[28] = 1, 2
	copy(base[16:20], lease.AsSlice())

	request := pendingDHCP{
		slave: slave, kind: dhcpMsgRequest, giaddr: netip.MustParseAddr("192.0.2.2"),
		server: server, address: lease, expires: now.Add(dhcpRequestLifetime),
	}
	key := dhcpTransactionFor(base, master)
	dhcpRequests[key] = request
	t.Cleanup(func() { delete(dhcpRequests, key) })
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
		match  bool
	}{
		{"no Option 82", func(pkt []byte) []byte { return pkt }, true},
		{"correct Option 82", func(pkt []byte) []byte { out, _ := insertAgentInfo(pkt, 3); return out }, true},
		{"wrong Option 82", func(pkt []byte) []byte { out, _ := insertAgentInfo(pkt, 4); return out }, false},
		{"wrong xid", func(pkt []byte) []byte { pkt[4]++; return pkt }, false},
		{"wrong MAC", func(pkt []byte) []byte { pkt[28]++; return pkt }, false},
		{"wrong IP", func(pkt []byte) []byte { pkt[19]++; return pkt }, false},
		{"wrong giaddr", func(pkt []byte) []byte { pkt[24]++; return pkt }, false},
		{"wrong server", func(pkt []byte) []byte { pkt[dhcpOptionsOff+5]++; return pkt }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := tc.change(append([]byte(nil), base...))
			reply, ok := matchDHCPReply(dhcpTransactionFor(pkt, master), pkt, parseDHCPOptions(pkt), dhcpMsgAck, now)
			if ok != tc.match || (ok && reply.slave != slave) {
				t.Fatalf("got downstream %p, match %v", reply.slave, ok)
			}
		})
	}
	if _, ok := matchDHCPReply(key, base, parseDHCPOptions(base), dhcpMsgAck, request.expires); ok {
		t.Fatal("expired request matched")
	}
	if canTrackDHCP(key, &Interface{Ifindex: 4}, now) {
		t.Fatal("another LAN can overwrite the pending request")
	}
	forgetDHCPTransactions(slave)
	if _, ok := dhcpRequests[key]; ok {
		t.Fatal("request survived downstream removal")
	}
}

func TestStopDHCPUnblocksReader(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ds := &dhcpSock{conn: conn, done: make(chan struct{})}
	iface := &Interface{dhcp: []*dhcpSock{ds}}
	stopped := make(chan struct{})
	go func() {
		dhcpReadLoop(ds)
		close(stopped)
	}()
	stopDHCP(iface)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("UDP reader is still running after shutdown")
	}
}
