# ipv4-relay

轻量级 IPv4 中继守护进程（DHCPv4 / ARP relay），Go 语言实现，单文件静态编译，无外部依赖。

下游（LAN）客户端通过中继从上游（WAN）DHCP 服务器获取 IPv4 地址。中继在上游接口广播请求，无需配置服务器地址，并通过 proxy ARP 和主机路由实现双向连通。

## 功能

- **DHCPv4 中继**（RFC 1542/2131/3046）
  - 下游接口接收客户端 DHCP 广播 -> 填 `giaddr` + 附加 Option 82 circuit-id -> 上游接口重新广播
  - 上游应答按已转发的 DHCP 请求匹配，只发回原下游接口。服务器不回显 Option 82 时也能定位，回显时校验 circuit-id 并剥除该选项
  - 从匹配的 DHCPACK 学习客户端，安装 proxy-ARP 表项和 `/32` 主机路由。收到已记录的租约持有者的 RELEASE/DECLINE 时清理
  - 通过邻居表事件和定期清理回收失效表项
  - 网关改写：下游接口地址按应答中的子网掩码可在客户端链路上直达时，将 Option 3 的首选网关改为该地址。缺少可用掩码或上游提供 Option 121 时保留服务器的网关和路由选项
- **ARP 中继（proxy ARP）**
  - 上游对客户端地址的 ARP 询问由本机代答，下游对上游地址的 ARP 询问同样代答
- **热重载**：`SIGHUP` 重读配置。读取、校验或绑定必需的 DHCP 端口失败时保留运行中的配置，并记录错误。接口增删、地址变化经 netlink 自动跟踪
- **非 root 运行**：配合 systemd `DynamicUser` + `AmbientCapabilities`，仅需 `CAP_NET_RAW` / `CAP_NET_ADMIN` / `CAP_NET_BIND_SERVICE`

## 编译

发布包使用 Go 1.27.3。

```sh
go build -trimpath -ldflags="-s -w" -o ipv4-relay ./cmd/ipv4-relay
```

交叉编译（如 linux/arm64 路由器）：

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ipv4-relay ./cmd/ipv4-relay
```

## 使用

```sh
ipv4-relay -c /etc/ipv4-relay/config.json [-l 0..7] [-f]
```

- `-c`：JSON 配置文件路径（必填）
- `-l`：日志级别 0..7（默认 4，warning）
- `-f`：输出到 stderr 而不是 syslog

配置示例（见 [config.json.example](config.json.example)）：

```json
{
  "interfaces": {
    "lan": { "ifname": "eth1", "arpproxy_routing": true },
    "wan": { "ifname": "eth0", "master": true, "arpproxy_routing": true }
  }
}
```

- `master: true` 标记上游接口（接收服务器应答的一侧）
- `arpproxy_routing`：为学到的客户端安装 `/32` 主机路由

### systemd

首次手动安装时，复制二进制、服务单元和示例配置。

```sh
install -m 755 ipv4-relay /usr/sbin/
install -m 644 ipv4-relay.service /usr/lib/systemd/system/
install -Dm 644 config.json.example /etc/ipv4-relay/config.json
```

将 `/etc/ipv4-relay/config.json` 中的 `interfaces.lan.ifname` 和 `interfaces.wan.ifname` 分别设为实际的下游和上游网卡名，再启动服务。

```sh
systemctl enable --now ipv4-relay
```

## 注意

- 本机自身不应再运行 DHCPv4 服务器（如 kea-dhcp4）监听相同接口，端口 67 会冲突
- 客户端获得的是上游网段地址，若上游有 NAT/防火墙策略，需相应放行该网段
- 下游为直连 DHCP 客户端。上游链路应由可信 DHCP 服务器提供租约，DHCP 本身不提供服务器身份认证

## 回归测试

在 Linux 上运行 `go test ./...`。网络回归测试需要 Python 3、iproute2、util-linux 和创建网络命名空间所需的权限。脚本在独立命名空间内创建虚拟接口并启动构建好的二进制。

```sh
go build -o /tmp/ipv4-relay ./cmd/ipv4-relay
sudo python3 tools/test_relay_linux.py /tmp/ipv4-relay
```

## 项目结构

```
cmd/ipv4-relay/    主程序入口
internal/relay/    引擎、配置、netlink 监控、DHCPv4/ARP 中继实现
```

## 许可证

[MIT](LICENSE)
