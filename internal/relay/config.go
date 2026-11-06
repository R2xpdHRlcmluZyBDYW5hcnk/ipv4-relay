package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Config holds global configuration flags.
type Config struct {
	ConfigFile      string
	LogLevelCmdline bool
}

var Cfg = Config{}

type jsonGlobal struct {
	LogLevel                        *int `json:"log_level"`
	StaleClientSweepIntervalSeconds *int `json:"stale_client_sweep_interval_seconds"`
}

type jsonIface struct {
	Ifname          *string `json:"ifname"`
	Master          *bool   `json:"master"`
	ArpproxyRouting *bool   `json:"arpproxy_routing"`
}

type jsonRoot struct {
	Global     *jsonGlobal          `json:"global"`
	Interfaces map[string]jsonIface `json:"interfaces"`
}

// fetchAddr4 refreshes an interface's cached IPv4 address list from the kernel.
func fetchAddr4(ifindex int) []IPAddr {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return nil
	}

	out := make([]IPAddr, 0, len(addrs))
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP.To4())
		if !ok {
			continue
		}
		ones, _ := a.Mask.Size()

		out = append(out, IPAddr{
			Addr:      ip,
			PrefixLen: uint8(ones),
			Tentative: a.Flags&unix.IFA_F_TENTATIVE != 0,
		})
	}
	return out
}

func refreshInterfaceAddresses(iface *Interface) {
	iface.Addr4 = fetchAddr4(iface.Ifindex)
}

// readConfig stages a complete configuration before touching running services.
func readConfig(path string) (jsonRoot, error) {
	var root jsonRoot
	data, err := os.ReadFile(path)
	if err != nil {
		return root, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return root, fmt.Errorf("parse config %s: %w", path, err)
	}
	if root.Interfaces == nil {
		return root, fmt.Errorf("config %s must define an interfaces object", path)
	}
	if root.Global != nil && root.Global.StaleClientSweepIntervalSeconds != nil {
		seconds := int64(*root.Global.StaleClientSweepIntervalSeconds)
		if seconds <= 0 || seconds > math.MaxInt64/int64(time.Second) {
			return root, fmt.Errorf("stale_client_sweep_interval_seconds is out of range")
		}
	}
	return root, nil
}

func planInterfaces(root jsonRoot) (map[string]*Interface, error) {
	next := make(map[string]*Interface, len(root.Interfaces))
	names := make(map[string]bool, len(root.Interfaces))
	indexes := make(map[int]bool, len(root.Interfaces))
	haveSlave := false
	for name, obj := range root.Interfaces {
		iface := &Interface{Name: name}
		setInterfaceDefaults(iface)
		if obj.Ifname != nil {
			iface.Ifname = *obj.Ifname
		} else if old := interfaces[name]; old != nil {
			iface.Ifname = old.Ifname
		}
		if ifname := iface.Ifname; ifname == "" || len(ifname) >= unix.IFNAMSIZ ||
			ifname == "." || ifname == ".." || strings.ContainsAny(ifname, "/:\x00") ||
			strings.IndexFunc(ifname, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("interface %q has an invalid or missing ifname", name)
		}
		if names[iface.Ifname] {
			return nil, fmt.Errorf("ifname %q is assigned to multiple relay interfaces", iface.Ifname)
		}
		names[iface.Ifname] = true
		if obj.Master != nil {
			iface.Master = *obj.Master
		}
		if obj.ArpproxyRouting != nil {
			iface.LearnRoutes = *obj.ArpproxyRouting
		}
		haveSlave = haveSlave || !iface.Master

		link, err := netlink.LinkByName(iface.Ifname)
		if err != nil {
			var missing netlink.LinkNotFoundError
			if !errors.As(err, &missing) {
				return nil, fmt.Errorf("resolve interface %q (%s): %w", name, iface.Ifname, err)
			}
			// A netlink event will bring a configured interface into service
			// once the device is created.
		} else {
			iface.Ifindex = link.Attrs().Index
			if indexes[iface.Ifindex] {
				return nil, fmt.Errorf("ifname %q resolves to a device already configured", iface.Ifname)
			}
			indexes[iface.Ifindex] = true
			iface.Running = link.Attrs().RawFlags&unix.IFF_RUNNING != 0
			refreshInterfaceAddresses(iface)
		}
		next[name] = iface
	}
	if !haveSlave {
		for _, iface := range next {
			iface.DHCPv4 = ModeDisabled
			iface.ARP = ModeDisabled
		}
	}
	return next, nil
}

func sameRelayInterface(old, next *Interface) bool {
	return old != nil && next != nil && old.Ifname == next.Ifname && old.Ifindex == next.Ifindex &&
		old.Running == next.Running && old.Master == next.Master &&
		old.DHCPv4 == next.DHCPv4 && old.ARP == next.ARP
}

func setInterfaceARP(iface *Interface, enable bool) {
	if iface.Ifindex != 0 {
		if err := arpSetup(iface, enable); err != nil {
			Warnf("proxy_arp on %s: %v", iface.Ifname, err)
		}
	}
}

// reloadServices handles device events. Configuration reloads stage new
// listeners before replacing the existing ones.
func reloadServices(iface *Interface) {
	if !iface.Running {
		disableServices(iface)
		return
	}
	setInterfaceARP(iface, true)
	if iface.DHCPv4 == ModeRelay && len(iface.dhcp) == 0 {
		if err := startDHCP(iface); err != nil {
			Errorf("%v", err)
		}
	}
}

func disableServices(iface *Interface) {
	stopDHCP(iface)
	forgetDHCPTransactions(iface)
	setInterfaceARP(iface, false)
}

// Reload validates and stages the new configuration before changing the
// old one. It runs on the Engine, or at startup before the Engine starts.
func Reload() error {
	root, err := readConfig(Cfg.ConfigFile)
	if err != nil {
		return err
	}
	next, err := planInterfaces(root)
	if err != nil {
		return err
	}

	staged := make([]*Interface, 0)
	for name, iface := range next {
		old := interfaces[name]
		if !iface.Running || iface.DHCPv4 != ModeRelay ||
			(sameRelayInterface(old, iface) && len(old.dhcp) > 0) {
			continue
		}
		if err := startDHCP(iface); err != nil {
			for _, pending := range staged {
				stopDHCP(pending)
			}
			return err
		}
		staged = append(staged, iface)
	}

	for name, old := range interfaces {
		if !sameRelayInterface(old, next[name]) {
			clearMirroredState(old)
			disableServices(old)
		}
	}
	for name, iface := range next {
		old := interfaces[name]
		if sameRelayInterface(old, iface) {
			if old.LearnRoutes && !iface.LearnRoutes {
				removeInterfaceRoutes(old)
			}
			if len(iface.dhcp) > 0 {
				old.dhcp = iface.dhcp
				for _, ds := range old.dhcp {
					ds.iface = old
				}
			} else if old.Master && len(old.dhcp) == 1 {
				startUpstreamClientPort(old)
			}
			old.LearnRoutes = iface.LearnRoutes
			old.Addr4 = iface.Addr4
			next[name] = old
		}
	}
	interfaces = next
	for _, iface := range interfaces {
		setInterfaceARP(iface, iface.Running)
	}
	reconcileMirrors()

	if global := root.Global; global != nil {
		if global.LogLevel != nil && !Cfg.LogLevelCmdline {
			SetLogLevel(*global.LogLevel)
			fmt.Fprintf(os.Stderr, "Log level set to %d\n", LogLevel())
		}
		if global.StaleClientSweepIntervalSeconds != nil {
			staleClientSweepInterval = time.Duration(*global.StaleClientSweepIntervalSeconds) * time.Second
		}
	}
	scheduleMirrorSweep()
	return nil
}
