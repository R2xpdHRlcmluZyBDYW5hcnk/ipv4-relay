package relay

import (
	"bytes"
	"testing"
)

// buildDHCP assembles a minimal BOOTP/DHCP packet: fixed header (zeros, op
// filled in), magic cookie, main options, End. The returned slice is always
// at least dhcpOptionsOff bytes.
func buildDHCP(mainOpts ...[]byte) []byte {
	pkt := make([]byte, dhcpOptionsOff)
	pkt[0] = bootpRequest
	pkt[1] = 1 // htype ethernet
	pkt[2] = 6 // hlen
	copy(pkt[dhcpCookieOff:dhcpOptionsOff], dhcpMagicCookie)
	for _, o := range mainOpts {
		pkt = append(pkt, o...)
	}
	return append(pkt, dhcpOptEnd)
}

// headerField overwrites a sname/file-sized chunk of the packet with an
// options area (must include its own End option).
func headerField(pkt []byte, off int, fieldOpts ...byte) []byte {
	copy(pkt[off:off+len(fieldOpts)], fieldOpts)
	return pkt
}

func optBytes(code byte, data ...byte) []byte {
	return append([]byte{code, byte(len(data))}, data...)
}

func findOpt(opts []dhcpOption, code byte) ([]byte, bool) {
	for _, o := range opts {
		if o.code == code {
			return o.data, true
		}
	}
	return nil, false
}

func TestParseDHCPOptionsBasics(t *testing.T) {
	pkt := buildDHCP(optBytes(dhcpOptMsgType, dhcpMsgDiscover), optBytes(dhcpOptRequested, 10, 0, 0, 1))
	opts := parseDHCPOptions(pkt)
	if opts == nil {
		t.Fatal("well-formed options area parsed as nil")
	}
	if mt, ok := findOpt(opts, dhcpOptMsgType); !ok || mt[0] != dhcpMsgDiscover {
		t.Fatalf("message type not found: %v", opts)
	}
	if d, ok := findOpt(opts, dhcpOptRequested); !ok || !bytes.Equal(d, []byte{10, 0, 0, 1}) {
		t.Fatalf("requested IP wrong: %v", d)
	}
}

func TestParseDHCPOptionsMalformed(t *testing.T) {
	// No End option anywhere: invalid.
	pkt := buildDHCP(optBytes(dhcpOptMsgType, dhcpMsgDiscover))
	trimmed := pkt[:len(pkt)-1]
	if opts := parseDHCPOptions(trimmed); opts != nil {
		t.Fatalf("unterminated options area should be nil, got %v", opts)
	}

	// Length running past the buffer: invalid.
	pkt = buildDHCP([]byte{dhcpOptMsgType, 99})
	for i := len(pkt); i < 300; i++ {
		pkt = append(pkt, 0)
	}
	if opts := parseDHCPOptions(pkt); opts != nil {
		t.Fatalf("overlong option length should be nil, got %v", opts)
	}
}

func TestParseDHCPOptionsOverloading(t *testing.T) {
	snameOpts := append(optBytes(dhcpOptMsgType, dhcpMsgRequest), dhcpOptEnd)
	fileOpts := append(optBytes(dhcpOptRequested, 10, 0, 0, 2), dhcpOptEnd)

	pkt := buildDHCP(optBytes(dhcpOptOverload, 3)) // both sname and file
	headerField(pkt, bootpSnameOff, snameOpts...)
	headerField(pkt, bootpFileOff, fileOpts...)

	opts := parseDHCPOptions(pkt)
	if mt, ok := findOpt(opts, dhcpOptMsgType); !ok || mt[0] != dhcpMsgRequest {
		t.Fatalf("message type from sname not found: %v", opts)
	}
	if d, ok := findOpt(opts, dhcpOptRequested); !ok || !bytes.Equal(d, []byte{10, 0, 0, 2}) {
		t.Fatalf("requested IP from file not found: %v", opts)
	}
}

func TestParseDHCPOptionsOverloadingSingleField(t *testing.T) {
	snameOpts := append(optBytes(dhcpOptMsgType, dhcpMsgInform), dhcpOptEnd)
	fileOpts := append(optBytes(dhcpOptRequested, 10, 0, 0, 2), dhcpOptEnd)

	// Overload=2: only sname parsed; file must be ignored.
	pkt := buildDHCP(optBytes(dhcpOptOverload, 2))
	headerField(pkt, bootpSnameOff, snameOpts...)
	headerField(pkt, bootpFileOff, fileOpts...)
	opts := parseDHCPOptions(pkt)
	if _, ok := findOpt(opts, dhcpOptMsgType); !ok {
		t.Fatalf("sname option missed with overload=2: %v", opts)
	}
	if _, ok := findOpt(opts, dhcpOptRequested); ok {
		t.Fatalf("file option must be ignored with overload=2: %v", opts)
	}

	// Overload=1: only file parsed.
	pkt = buildDHCP(optBytes(dhcpOptOverload, 1))
	headerField(pkt, bootpSnameOff, snameOpts...)
	headerField(pkt, bootpFileOff, fileOpts...)
	opts = parseDHCPOptions(pkt)
	if _, ok := findOpt(opts, dhcpOptRequested); !ok {
		t.Fatalf("file option missed with overload=1: %v", opts)
	}
	if _, ok := findOpt(opts, dhcpOptMsgType); ok {
		t.Fatalf("sname option must be ignored with overload=1: %v", opts)
	}
}

func TestParseDHCPOptionsBogusOverloadHint(t *testing.T) {
	// Overload claims sname holds options but it is a zero-filled legacy
	// field: the main area's options must still come through, and the
	// garbage in the claimed field must not invalidate the packet.
	pkt := buildDHCP(optBytes(dhcpOptMsgType, dhcpMsgDiscover), optBytes(dhcpOptOverload, 2))
	opts := parseDHCPOptions(pkt)
	if mt, ok := findOpt(opts, dhcpOptMsgType); !ok || mt[0] != dhcpMsgDiscover {
		t.Fatalf("main options lost with bogus overload hint: %v", opts)
	}
}

func TestInsertAgentInfo(t *testing.T) {
	pkt := buildDHCP(optBytes(dhcpOptMsgType, dhcpMsgDiscover))
	out, ok := insertAgentInfo(pkt, 7)
	if !ok {
		t.Fatal("insertion failed")
	}
	opts := parseDHCPOptions(out)
	d, found := findOpt(opts, dhcpOptAgentInfo)
	if !found {
		t.Fatalf("option 82 missing after insert: %x", out[dhcpOptionsOff:])
	}
	if idx, ok := parseCircuitID(d); !ok || idx != 7 {
		t.Fatalf("circuit-id roundtrip failed: %d %v", idx, ok)
	}
	// Original message type must survive untouched.
	if mt, ok := findOpt(opts, dhcpOptMsgType); !ok || mt[0] != dhcpMsgDiscover {
		t.Fatalf("message type corrupted: %v", opts)
	}

	// Already carrying option 82 (downstream relay): passed through as-is.
	if out2, ok := insertAgentInfo(out, 8); !ok || !bytes.Equal(out2, out) {
		t.Fatal("packet with existing option 82 must be returned unmodified")
	}

	// Packet too large to append the option: refused, caller falls back.
	// 241 bytes of base + 1151 of options = 1392, the last size that fits;
	// one byte more must be refused.
	fits := buildDHCP(make([]byte, 1392-(dhcpOptionsOff+1)))
	if out, ok := insertAgentInfo(fits, 7); !ok || len(out) > dhcpMaxPktSize {
		t.Fatalf("boundary packet should fit: ok=%v len=%d", ok, len(out))
	}
	tooBig := buildDHCP(make([]byte, 1393-(dhcpOptionsOff+1)))
	if _, ok := insertAgentInfo(tooBig, 7); ok {
		t.Fatal("oversized packet must be refused")
	}

	// Malformed options area (no End): refused.
	if _, ok := insertAgentInfo(pkt[:len(pkt)-1], 7); ok {
		t.Fatal("unterminated options area must be refused")
	}
}

func TestStripAgentInfo(t *testing.T) {
	pkt := buildDHCP(
		optBytes(dhcpOptMsgType, dhcpMsgAck),
		optBytes(dhcpOptAgentInfo, agentSubOptCircuitID, 4, 1, 2, 3, 4),
		optBytes(dhcpOptRequested, 10, 0, 0, 5),
	)

	out := stripAgentInfo(pkt)
	opts := parseDHCPOptions(out)
	if _, found := findOpt(opts, dhcpOptAgentInfo); found {
		t.Fatal("option 82 survived stripping")
	}
	if mt, ok := findOpt(opts, dhcpOptMsgType); !ok || mt[0] != dhcpMsgAck {
		t.Fatal("message type lost while stripping")
	}
	if d, ok := findOpt(opts, dhcpOptRequested); !ok || !bytes.Equal(d, []byte{10, 0, 0, 5}) {
		t.Fatal("sibling option corrupted while stripping")
	}

	// No option 82 to begin with: packet comes back byte-identical.
	plain := buildDHCP(optBytes(dhcpOptMsgType, dhcpMsgNak))
	if out := stripAgentInfo(plain); !bytes.Equal(out, plain) {
		t.Fatal("clean packet must be returned unchanged")
	}
}

func TestParseCircuitIDSkipsOtherSubOptions(t *testing.T) {
	// agent sub-option 2 (remote-id) first, circuit-id second.
	payload := append(optBytes(2, 'r', 'i'), optBytes(agentSubOptCircuitID, 9, 0, 0, 0)...)
	idx, ok := parseCircuitID(payload)
	if !ok || idx != 9 {
		t.Fatalf("circuit-id after remote-id not found: %d %v", idx, ok)
	}
	// Truncated circuit-id: not found.
	payload = []byte{agentSubOptCircuitID, 4, 1, 2}
	if _, ok := parseCircuitID(payload); ok {
		t.Fatal("truncated circuit-id must not parse")
	}
}

// guard against accidental big-endian drift with the ipv6-relay interface-id
func TestCircuitIDEndianness(t *testing.T) {
	payload := []byte{agentSubOptCircuitID, 4, 0x01, 0x02, 0x03, 0x04}
	got, ok := parseCircuitID(payload)
	if !ok || got != 0x04030201 { // 01 02 03 04 little-endian = 0x04030201
		t.Fatalf("endianness mismatch: got %#x", got)
	}
}
