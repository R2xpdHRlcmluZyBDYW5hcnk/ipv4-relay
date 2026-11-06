package relay

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	dhcpRequestLifetime = 2 * time.Minute
	maxPendingDHCP      = 4096
)

type dhcpClient struct {
	mac [6]byte
	id  string
}

type dhcpTransaction struct {
	xid    uint32
	mac    [6]byte
	master *Interface
}

type pendingDHCP struct {
	slave   *Interface
	client  dhcpClient
	kind    int
	giaddr  netip.Addr
	server  netip.Addr
	address netip.Addr
	expires time.Time
}

// DHCP requests and learned lease owners are used only by the Engine.
var (
	dhcpRequests = map[dhcpTransaction]pendingDHCP{}
	dhcpLeases   = map[mirroredNeighKey]dhcpClient{}
)

func dhcpClientFrom(data []byte, opts []dhcpOption) dhcpClient {
	client := dhcpClient{mac: [6]byte(data[28:34])}
	for _, opt := range opts {
		if opt.code == dhcpOptClientID {
			client.id = string(opt.data)
			break
		}
	}
	return client
}

func dhcpOptionAddr(opts []dhcpOption, code byte) netip.Addr {
	for _, opt := range opts {
		if opt.code == code && len(opt.data) == 4 {
			return netip.AddrFrom4([4]byte(opt.data))
		}
	}
	return netip.Addr{}
}

func dhcpTransactionFor(data []byte, master *Interface) dhcpTransaction {
	return dhcpTransaction{binary.BigEndian.Uint32(data[4:8]), [6]byte(data[28:34]), master}
}

func canTrackDHCP(key dhcpTransaction, slave *Interface, now time.Time) bool {
	if existing, ok := dhcpRequests[key]; ok && now.Before(existing.expires) {
		// Never move a live transaction to another downstream interface.
		return existing.slave == slave
	}
	if len(dhcpRequests) >= maxPendingDHCP {
		for key, request := range dhcpRequests {
			if !now.Before(request.expires) {
				delete(dhcpRequests, key)
			}
		}
	}
	return len(dhcpRequests) < maxPendingDHCP
}

func matchDHCPReply(key dhcpTransaction, data []byte, opts []dhcpOption, kind int, now time.Time) (pendingDHCP, bool) {
	request, ok := dhcpRequests[key]
	if !ok || !now.Before(request.expires) || len(request.slave.dhcp) == 0 {
		return pendingDHCP{}, false
	}
	switch request.kind {
	case dhcpMsgDiscover:
		if kind != dhcpMsgOffer {
			return pendingDHCP{}, false
		}
	case dhcpMsgRequest:
		if kind != dhcpMsgAck && kind != dhcpMsgNak {
			return pendingDHCP{}, false
		}
	case dhcpMsgInform:
		if kind != dhcpMsgAck {
			return pendingDHCP{}, false
		}
	default:
		return pendingDHCP{}, false
	}
	giaddr := netip.AddrFrom4([4]byte(data[24:28]))
	if !giaddr.IsUnspecified() && giaddr != request.giaddr {
		return pendingDHCP{}, false
	}
	if request.server.IsValid() && dhcpOptionAddr(opts, dhcpOptServerID) != request.server {
		return pendingDHCP{}, false
	}
	if request.kind == dhcpMsgRequest && kind == dhcpMsgAck {
		yiaddr := netip.AddrFrom4([4]byte(data[16:20]))
		if !yiaddr.IsGlobalUnicast() || (request.address.IsGlobalUnicast() && yiaddr != request.address) {
			return pendingDHCP{}, false
		}
	}
	if client := dhcpClientFrom(data, opts); client.id != "" && request.client.id != "" && client.id != request.client.id {
		return pendingDHCP{}, false
	}
	for _, opt := range opts {
		if opt.code == dhcpOptAgentInfo {
			idx, ok := parseCircuitID(opt.data)
			if !ok || idx != request.slave.Ifindex {
				return pendingDHCP{}, false
			}
		}
	}
	return request, true
}

func forgetDHCPTransactions(iface *Interface) {
	for key, request := range dhcpRequests {
		if key.master == iface || request.slave == iface {
			delete(dhcpRequests, key)
		}
	}
}
