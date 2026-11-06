"""Exercise ipv4-relay against real sockets and routes in a private netns."""

import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


CLIENT = bytes.fromhex("02aabbccddee")
OTHER = bytes.fromhex("020011223344")
SERVER = "192.0.2.2"
UPSTREAM_ROUTER = "192.0.2.254"
BROADCAST = "255.255.255.255"


def ip(*args):
    return subprocess.check_output(["ip", *args], text=True).strip()


def wait_for(condition, message):
    until = time.monotonic() + 5
    while time.monotonic() < until:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(message)


def make_links():
    ip("link", "set", "lo", "up")
    for relay, peer, subnet in (
        ("wan0", "wpeer", "192.0.2"),
        ("lana", "apeer", "198.51.100"),
        ("lanb", "bpeer", "203.0.113"),
    ):
        ip("link", "add", relay, "type", "veth", "peer", "name", peer)
        for index, iface in enumerate((relay, peer), start=1):
            ip("addr", "add", f"{subnet}.{index}/24", "dev", iface)
            ip("link", "set", iface, "up")
            # Both ends of each veth pair are in this test namespace.
            Path(f"/proc/sys/net/ipv4/conf/{iface}/accept_local").write_text("1")
            Path(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter").write_text("0")
    Path("/proc/sys/net/ipv4/conf/all/rp_filter").write_text("0")


def option(code, value):
    return bytes((code, len(value))) + value


def packet(kind, xid, *, reply=False, mac=CLIENT, yiaddr=None, ciaddr=None, options=b""):
    msg = bytearray(240)
    msg[:3] = bytes((2 if reply else 1, 1, 6))
    struct.pack_into("!I", msg, 4, xid)
    struct.pack_into("!H", msg, 10, 0x8000)
    msg[28:34] = mac
    msg[236:240] = b"\x63\x82\x53\x63"
    if yiaddr:
        msg[16:20] = socket.inet_aton(yiaddr)
    if ciaddr:
        msg[12:16] = socket.inet_aton(ciaddr)
    return msg + option(53, bytes((kind,))) + options + b"\xff"


def udp(iface, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", port))
    sock.settimeout(5)
    return sock


def receive(sock, xid, op=2):
    while True:
        payload = sock.recv(4096)
        if payload[0] == op:
            break
    assert payload[4:8] == struct.pack("!I", xid), payload.hex()
    return payload


def expect_silence(*sockets, op=2):
    for sock in sockets:
        sock.settimeout(0.15)
        try:
            while True:
                unexpected = sock.recv(4096)
                if unexpected[0] == op:
                    break
        except TimeoutError:
            continue
        finally:
            sock.settimeout(5)
        raise AssertionError(f"unexpected DHCP reply: {unexpected.hex()}")


def host_route(addr):
    return json.loads(ip("-j", "route", "show", "exact", f"{addr}/32"))


def proxy_neighbor(addr):
    return ip("neigh", "show", "proxy", "to", addr, "dev", "wan0")


def socket_handles(proc):
    return {target for path in Path(f"/proc/{proc.pid}/fd").iterdir()
            if (target := os.readlink(path)).startswith("socket:[")}


def run(command):
    make_links()
    config = {"global": {"log_level": 7, "stale_client_sweep_interval_seconds": 60}, "interfaces": {
        "up": {"ifname": "wan0", "master": True},
        "a": {"ifname": "lana"},
        "b": {"ifname": "lanb"},
    }}
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp).chmod(0o755)
        path = Path(tmp, "config.json")
        path.write_text(json.dumps(config))
        log = Path(tmp, "relay.log")
        with log.open("w") as output:
            proc = subprocess.Popen([*command, "-f", "-c", str(path)], stdout=output, stderr=output)
            try:
                wait_for(lambda: "Log level set to 7" in log.read_text(), "relay failed to start")
                exercise(proc, path, log, config)
            except Exception:
                print(log.read_text(), file=sys.stderr)
                raise
            finally:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=5)

        path.write_text("{")
        failed = subprocess.run([*command, "-f", "-c", str(path)], capture_output=True, timeout=5)
        assert failed.returncode != 0 and b"Unable to load relay configuration" in failed.stderr
        print("PASS invalid startup reports failure")


def exercise(proc, path, log, config):
    def reload_config(value, success=True):
        message = "Log level set to 7" if success else "Unable to reload relay configuration"
        count = log.read_text().count(message)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        proc.send_signal(signal.SIGHUP)
        wait_for(lambda: log.read_text().count(message) > count, f"reload failed to report: {message}")
        assert proc.poll() is None

    server_id = option(54, socket.inet_aton(SERVER))
    mask = option(1, bytes((255, 255, 255, 0)))
    router = option(3, socket.inet_aton(UPSTREAM_ROUTER))

    with udp("wpeer", 67) as server, udp("wpeer", 1067) as wrong_port, \
            udp("apeer", 68) as client_a, udp("bpeer", 68) as client_b:

        def request(client, xid, addr, options=b""):
            requested = option(50, socket.inet_aton(addr))
            client.sendto(packet(3, xid, options=requested + server_id + options), (BROADCAST, 67))
            forwarded = receive(server, xid, op=1)
            assert option(82, b"\x01\x04" + struct.pack("<I", socket.if_nametoindex(
                "lana" if client is client_a else "lanb"))) in forwarded[240:]

        def ack(sender, xid, addr, *, extra=b"", dest_port=67, mac=CLIENT):
            sender.sendto(packet(5, xid, reply=True, yiaddr=addr, mac=mac,
                                 options=server_id + mask + router + extra), (BROADCAST, dest_port))

        addr = "192.0.2.77"
        ack(server, 1, addr)
        expect_silence(client_a, client_b)
        assert not host_route(addr) and not proxy_neighbor(addr)

        client_a.sendto(packet(1, 2), (BROADCAST, 67))
        receive(server, 2, op=1)
        server.sendto(packet(2, 2, reply=True, yiaddr=addr, options=server_id), (BROADCAST, 67))
        receive(client_a, 2)

        request(client_a, 2, addr)
        ack(wrong_port, 2, addr)
        ack(server, 3, addr)
        ack(server, 2, addr, mac=OTHER)
        ack(server, 2, addr, extra=option(82, b"\x01\x04" + struct.pack("<I", socket.if_nametoindex("lanb"))))
        expect_silence(client_a, client_b)
        assert not host_route(addr) and not proxy_neighbor(addr)
        print("PASS unsolicited and mismatched ACKs do not reach clients or change kernel state")

        ack(server, 2, addr, dest_port=68)
        assert router in receive(client_a, 2)[240:]
        expect_silence(client_b)
        assert [r["dev"] for r in host_route(addr)] == ["lana"]
        assert proxy_neighbor(addr)
        assert not ip("neigh", "show", "to", addr, "dev", "lanb")
        print("PASS ACK without Option 82 reaches only the originating LAN and retains an on-link gateway")

        client_a.sendto(packet(7, 4, ciaddr=addr, mac=OTHER, options=server_id), (BROADCAST, 67))
        expect_silence(server, op=1)
        assert host_route(addr) and proxy_neighbor(addr)
        client_a.sendto(packet(7, 5, ciaddr=addr, options=server_id), (BROADCAST, 67))
        receive(server, 5, op=1)
        wait_for(lambda: not host_route(addr) and not proxy_neighbor(addr), "owner release left a mirror")
        print("PASS only the recorded lease owner can remove the mirror")

        addr_b = "203.0.113.78"
        request(client_b, 6, addr_b)
        ack(server, 6, addr_b)
        assert option(3, socket.inet_aton("203.0.113.1")) in receive(client_b, 6)[240:]
        print("PASS on-link LAN gateway is rewritten")

        initial_handles = socket_handles(proc)
        for _ in range(3):
            reload_config(config)
            assert socket_handles(proc) == initial_handles, "no-op reload replaced listeners"

        reload_config("{", success=False)
        assert socket_handles(proc) == initial_handles
        assert Path("/proc/sys/net/ipv4/conf/lana/proxy_arp").read_text().strip() == "1"
        request(client_a, 7, "192.0.2.79")
        ack(server, 7, "192.0.2.79")
        receive(client_a, 7)
        print("PASS malformed reload preserves the active listeners and DHCP flow")

        old_lease = "203.0.113.79"
        unrelated = "203.0.113.80"
        ip("route", "add", f"{old_lease}/32", "dev", "lanb", "proto", "static", "scope", "link", "metric", "1024")
        ip("neigh", "add", "proxy", old_lease, "dev", "wan0")
        ip("route", "add", f"{unrelated}/32", "dev", "lanb", "proto", "boot", "scope", "link", "metric", "1024")

        lan_b = config["interfaces"].pop("b")
        reload_config(config)
        assert not host_route(addr_b) and not proxy_neighbor(addr_b)
        assert not host_route(old_lease) and not proxy_neighbor(old_lease)
        assert host_route(unrelated), "removed a route belonging to another program"
        print("PASS removing a LAN clears current and previous-run mirrors")

        config["interfaces"]["b"] = lan_b
        with udp("lanb", 67):
            reload_config(config, success=False)
            request(client_a, 8, "192.0.2.80")
            ack(server, 8, "192.0.2.80")
            receive(client_a, 8)
        for _ in range(3):
            reload_config(config)
            del config["interfaces"]["b"]
            reload_config(config)
            config["interfaces"]["b"] = lan_b
        reload_config(config)
        assert len(socket_handles(proc)) == len(initial_handles)
        waits = [p.read_text().strip() for p in Path(f"/proc/{proc.pid}/task").glob("*/wchan") if p.exists()]
        assert all("skb_wait_for_more_packets" not in wait for wait in waits), waits
        request(client_b, 9, addr_b)
        ack(server, 9, addr_b)
        receive(client_b, 9)
        print("PASS bind failure rolls back and repeated listener replacement leaves no blocked readers")


if __name__ == "__main__":
    original = os.stat("/proc/self/ns/net").st_ino
    if len(sys.argv) >= 4 and sys.argv[1] == "--inside":
        if original == int(sys.argv[2]):
            sys.exit("Refusing to change the caller's network namespace")
        run(sys.argv[3:])
    elif len(sys.argv) >= 2:
        subprocess.run(
            ["unshare", "--net", "--", sys.executable, __file__, "--inside", str(original), *sys.argv[1:]],
            check=True,
        )
    else:
        sys.exit(f"usage: {sys.argv[0]} /path/to/ipv4-relay")
