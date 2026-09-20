#!/usr/bin/env python3
"""Minimal DHCPv4 DORA probe: Discover -> Offer -> Request -> Ack on one interface.

Sends with the broadcast flag set so replies come back as broadcasts a plain
UDP socket can receive (the relay delivers broadcast-flag replies by
broadcasting on the client interface). Prints every reply it sees.
"""
import os
import random
import socket
import struct
import sys
import time

IFACE = sys.argv[1] if len(sys.argv) > 1 else "lan1"
MAC = bytes([0x02, 0xDE, 0xAD, 0xBE, 0xEF, random.randrange(0x10, 0xFF)])
XID = random.randrange(1 << 32)

OPT_END = 255
MT_DISCOVER, MT_OFFER, MT_REQUEST, MT_ACK, MT_NAK = 1, 2, 3, 5, 6
MT_NAMES = {MT_DISCOVER: "DISCOVER", MT_OFFER: "OFFER", MT_REQUEST: "REQUEST",
            MT_ACK: "ACK", MT_NAK: "NAK"}


def opt(code, payload):
    return bytes([code, len(payload)]) + payload


def build(msg_type, server_id=None, requested=None):
    opts = opt(53, bytes([msg_type]))
    if server_id:
        opts += opt(54, server_id)
    if requested:
        opts += opt(50, requested)
    opts += opt(55, bytes([1, 3, 6, 15, 28, 51, 58, 59]))
    # PROBE_PAD=n stuffs a private-use option so the packet exceeds the
    # relay's option-82 insert limit (~1392 bytes): exercises the relay's
    # "relay without option 82" fallback on the DISCOVER only.
    pad = int(os.environ.get("PROBE_PAD", "0"))
    if pad and msg_type == MT_DISCOVER:
        # Option length is a single byte, so stuff the padding as several
        # private-use options.
        while pad > 0:
            n = min(pad, 255)
            opts += opt(223, bytes(n))
            pad -= n
    opts += b"\xff"

    pkt = struct.pack("!BBBBIHH", 1, 1, 6, 0, XID, 0, 0x8000)  # op..flags
    pkt += bytes(4)          # ciaddr
    pkt += bytes(4)          # yiaddr
    pkt += bytes(4)          # siaddr
    pkt += bytes(4)          # giaddr
    pkt += MAC + bytes(10)   # chaddr
    pkt += bytes(64)         # sname
    pkt += bytes(128)        # file
    pkt += b"\x63\x82\x53\x63" + opts
    return pkt


def parse(pkt):
    if len(pkt) < 240 or pkt[0] != 2:
        return None
    xid, = struct.unpack("!I", pkt[4:8])
    if xid != XID:
        return None
    opts, off = {}, 240
    while off + 1 <= len(pkt):
        code = pkt[off]
        if code == 0:
            off += 1
            continue
        if code == 255 or off + 2 > len(pkt):
            break
        ln = pkt[off + 1]
        opts[code] = pkt[off + 2:off + 2 + ln]
        off += 2 + ln
    return {
        "yiaddr": socket.inet_ntoa(pkt[16:20]),
        "msg": opts.get(53, b"\0")[0],
        "server": opts.get(54, b""),
        "leaset": struct.unpack("!I", opts[51])[0] if 51 in opts else 0,
    }


def recv_offers(s, want, seconds):
    end = time.time() + seconds
    while time.time() < end:
        s.settimeout(max(0.2, end - time.time()))
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            break
        r = parse(data)
        if r:
            print("  <- %-7s yiaddr=%s from=%s lease=%ss" %
                  (MT_NAMES.get(r["msg"], r["msg"]), r["yiaddr"], addr[0], r["leaset"]))
            if r["msg"] == want:
                return r
    return None


def release(s, yiaddr, server):
    # Best-effort DHCPRELEASE so the upstream lease table and the relay's
    # mirrored-client state get torn down after the probe.
    pkt = struct.pack("!BBBBIHH", 1, 1, 6, 0, XID, 0, 0)
    pkt += socket.inet_aton(yiaddr)  # ciaddr
    pkt += bytes(4) + bytes(4) + bytes(4)
    pkt += MAC + bytes(10) + bytes(64) + bytes(128)
    pkt += b"\x63\x82\x53\x63" + opt(53, bytes([7])) + opt(54, server) + b"\xff"
    s.sendto(pkt, ("255.255.255.255", 67))
    print("  -> RELEASE  ciaddr=%s" % yiaddr)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, 25, IFACE.encode() + b"\0")  # SO_BINDTODEVICE
    s.bind(("0.0.0.0", 68))

    print("probe if=%s mac=%s xid=%08x" % (IFACE, MAC.hex(":"), XID))

    for attempt in range(2):
        s.sendto(build(MT_DISCOVER), ("255.255.255.255", 67))
        print("  -> DISCOVER (attempt %d)" % (attempt + 1))
        offer = recv_offers(s, MT_OFFER, 8)
        if offer:
            break
    if not offer:
        print("FAIL: no OFFER")
        return 1

    s.sendto(build(MT_REQUEST, offer["server"],
                   socket.inet_aton(offer["yiaddr"])), ("255.255.255.255", 67))
    print("  -> REQUEST  requested=%s server=%s" % (offer["yiaddr"], socket.inet_ntoa(offer["server"])))
    ack = recv_offers(s, MT_ACK, 8)
    if not ack:
        print("FAIL: no ACK")
        return 1
    print("PASS: %s leased via relay on %s" % (ack["yiaddr"], IFACE))

    time.sleep(int(os.environ.get("PROBE_SLEEP", "1")))
    release(s, ack["yiaddr"], ack["server"])
    return 0


sys.exit(main())
