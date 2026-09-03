package relay

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

// bindToDevice performs SO_BINDTODEVICE to scope a socket to a single
// interface.
func bindToDevice(fd int, ifname string) error {
	return unix.BindToDevice(fd, ifname)
}

// setsockoptInt is a small readability wrapper.
func setsockoptInt(fd, level, opt, val int) error {
	return unix.SetsockoptInt(fd, level, opt, val)
}

// sockaddrIn4 builds a unix.SockaddrInet4 for dest:port.
func sockaddrIn4(dest netip.Addr, port int) *unix.SockaddrInet4 {
	sa := &unix.SockaddrInet4{Port: port}
	sa.Addr = dest.As4()
	return sa
}

// closeFD closes a raw fd, ignoring errors on an already-closed/invalid fd.
func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

// broadcastAddr is the limited broadcast address client requests are
// relayed to on a master interface: DHCPv4 is broadcast-based, so a
// plug-and-play relay simply re-broadcasts upstream instead of needing a
// configured server address. The server unicasts its replies back to the
// giaddr we stamped, which is this host's address on the master interface.
var broadcastAddr = netip.MustParseAddr("255.255.255.255")