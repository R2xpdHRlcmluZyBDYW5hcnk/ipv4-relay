# ipv4-relay

A lightweight IPv4 relay daemon (DHCPv4 / ARP relay), written in Go and built as a single static binary with no external runtime dependencies.

Downstream (LAN) clients obtain IPv4 addresses from an upstream (WAN) DHCP server through the relay. The relay broadcasts requests on the upstream interface, so no server address needs to be configured, and uses proxy ARP and host routes to provide bidirectional connectivity.

## Features

- **DHCPv4 relay** (RFC 1542/2131/3046)
  - Receives client DHCP broadcasts on downstream interfaces, sets `giaddr`, adds an Option 82 circuit-id, and rebroadcasts the requests on the upstream interface.
  - Matches upstream replies to forwarded DHCP requests and sends them only to the original downstream interface. Replies can be routed even if the server does not echo Option 82. When the server echoes it, the relay validates the circuit-id and removes the option.
  - Learns clients from matching DHCPACK messages and installs proxy ARP entries and `/32` host routes. Cleans up these entries when it receives a RELEASE or DECLINE from the recorded lease holder.
  - Removes stale entries in response to neighbor table events and through periodic cleanup.
  - Rewrites the preferred gateway in Option 3 to the downstream interface address when that address is directly reachable on the client's link according to the subnet mask in the reply. Preserves the server's gateway and route options if no usable mask is available or the upstream server supplies Option 121.
- **ARP relay (proxy ARP)**
  - Answers upstream ARP requests for client addresses and downstream ARP requests for upstream addresses on their behalf.
- **Hot reload**: `SIGHUP` reloads the configuration. If reading or validating the configuration, or binding a required DHCP port, fails, the relay keeps the active configuration and logs the error. Interface additions, removals, and address changes are tracked automatically through netlink.
- **Non-root operation**: Uses systemd `DynamicUser` and `AmbientCapabilities`, requiring only `CAP_NET_RAW`, `CAP_NET_ADMIN`, and `CAP_NET_BIND_SERVICE`.

## Build

Release binaries are built with Go 1.27.3.

```sh
go build -trimpath -ldflags="-s -w" -o ipv4-relay ./cmd/ipv4-relay
```

To cross-compile (for example, for a linux/arm64 router):

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ipv4-relay ./cmd/ipv4-relay
```

## Usage

```sh
ipv4-relay -c /etc/ipv4-relay/config.json [-l 0..7] [-f]
```

- `-c`: Path to the JSON configuration file (required).
- `-l`: Log level from 0 to 7 (default: 4, warning).
- `-f`: Log to stderr instead of syslog.

Example configuration (see [config.json.example](config.json.example)):

```json
{
  "interfaces": {
    "lan": { "ifname": "eth1", "arpproxy_routing": true },
    "wan": { "ifname": "eth0", "master": true, "arpproxy_routing": true }
  }
}
```

- `master: true`: Marks the upstream interface (the side that receives server replies).
- `arpproxy_routing`: Installs `/32` host routes for learned clients.

### systemd

For an initial manual installation, copy the binary, service unit, and example configuration:

```sh
install -m 755 ipv4-relay /usr/sbin/
install -m 644 ipv4-relay.service /usr/lib/systemd/system/
install -Dm 644 config.json.example /etc/ipv4-relay/config.json
```

Set `interfaces.lan.ifname` and `interfaces.wan.ifname` in `/etc/ipv4-relay/config.json` to the actual downstream and upstream interface names, respectively, then start the service:

```sh
systemctl enable --now ipv4-relay
```

## Notes

- Do not run another DHCPv4 server (such as kea-dhcp4) on the same host listening on the same interfaces, as it will conflict on port 67.
- Clients receive addresses from the upstream subnet. If the upstream network has NAT or firewall rules, adjust them to allow traffic from that subnet.
- Downstream DHCP clients must be directly connected. The upstream link should receive leases from a trusted DHCP server; DHCP itself does not authenticate servers.

## Regression Tests

Run `go test ./...` on Linux. The network regression tests require Python 3, iproute2, util-linux, and permission to create network namespaces. The script creates virtual interfaces in isolated namespaces and starts the compiled binary.

```sh
go build -o /tmp/ipv4-relay ./cmd/ipv4-relay
sudo python3 tools/test_relay_linux.py /tmp/ipv4-relay
```

## Project Structure

```
cmd/ipv4-relay/    Main program entry point
internal/relay/    Engine, configuration, netlink monitoring, and DHCPv4/ARP relay implementation
```

## License

[MIT](LICENSE)
