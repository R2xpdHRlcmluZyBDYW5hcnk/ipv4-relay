# ipv4-relay

轻量级 IPv4 中继守护进程（DHCPv4 / ARP relay），Go 语言实现，单文件静态编译，无外部依赖。

适用于将下游（LAN）网段「透明桥接」到上游（WAN）广播域的场景：下游客户端发出的 DHCPv4 请求经中继打上 Option 82 后在上游广播，上游 DHCP 服务器直接给客户端分配上游网段的地址，配合 proxy-ARP 与主机路由实现双向可达。即插即用——不需要指定 DHCP 服务器地址，因为 DHCPv4 本身就是广播协议。

## 功能

- **DHCPv4 中继**（RFC 1542/2131/3046）
  - 下游接口接收客户端 DHCP 广播 -> 填 `giaddr` + 附加 Option 82 circuit-id -> 上游接口重新广播
  - 上游服务器应答按 circuit-id 转发回对应下游接口，并剥除 Option 82
  - 从 DHCPACK 自动学习客户端：安装 proxy-ARP 表项和 `/32` 主机路由；RELEASE/DECLINE 时立即拆除
  - 邻居表事件 + 周期清扫兜底，客户端消失后自动回收表项
- **ARP 中继（proxy ARP）**
  - 上游对客户端地址的 ARP 询问由本机代答，下游对上游地址的 ARP 询问同样代答
- **热重载**：`SIGHUP` 重读配置；接口增删、地址变化经 netlink 自动跟踪
- **非 root 运行**：配合 systemd `DynamicUser` + `AmbientCapabilities`，仅需 `CAP_NET_RAW` / `CAP_NET_ADMIN` / `CAP_NET_BIND_SERVICE`

## 编译

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

```sh
install -m 755 ipv4-relay /usr/sbin/
install -m 644 ipv4-relay.service /usr/lib/systemd/system/
install -m 644 config.json.example /etc/ipv4-relay/config.json  # 按需修改
systemctl enable --now ipv4-relay
```

## 注意

- 本机自身不应再运行 DHCPv4 服务器（如 kea-dhcp4）监听相同接口，端口 67 会冲突
- 客户端获得的是上游网段地址，若上游有 NAT/防火墙策略，需相应放行该网段

## 项目结构

```
cmd/ipv4-relay/    主程序入口
internal/relay/    引擎、配置、netlink 监控、DHCPv4/ARP 中继实现
```

## 许可证

[MIT](LICENSE)
