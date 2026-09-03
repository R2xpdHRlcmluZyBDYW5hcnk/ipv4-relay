package relay

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

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

// findOrCreateInterface returns an existing interface or initializes a new one.
func findOrCreateInterface(name string) *Interface {
	if i, ok := interfaces[name]; ok {
		return i
	}

	i := &Interface{Name: name}
	setInterfaceDefaults(i)
	interfaces[name] = i
	return i
}

// parseInterfaceJSON parses configuration for an interface.
func parseInterfaceJSON(name string, obj jsonIface) error {
	iface := findOrCreateInterface(name)

	if iface.Ifname == "" && obj.Ifname == nil {
		return fmt.Errorf("interface %q has no ifname configured", name)
	}

	if obj.Ifname != nil {
		newIfname := *obj.Ifname
		link, err := netlink.LinkByName(newIfname)
		if err != nil {
			return fmt.Errorf("interface %q (%s): %w", name, newIfname, err)
		}

		if iface.Ifindex != 0 &&
			(iface.Ifname != newIfname || iface.Ifindex != link.Attrs().Index) {
			disableServices(iface)
			clearMirroredState(iface)
		}

		iface.Ifname = newIfname
		iface.Ifindex = link.Attrs().Index
		iface.Running = link.Attrs().RawFlags&unix.IFF_RUNNING != 0
		refreshInterfaceAddresses(iface)
	}

	iface.Inuse = true

	if obj.Master != nil {
		iface.Master = *obj.Master
	}
	if obj.ArpproxyRouting != nil {
		iface.LearnRoutes = *obj.ArpproxyRouting
	}

	return nil
}

// loadConfigJSON reads and parses the JSON configuration file.
func loadConfigJSON(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		Errorf("Failed to read JSON config from %s: %v", path, err)
		return
	}

	var root jsonRoot
	if err := json.Unmarshal(data, &root); err != nil {
		Errorf("Failed to parse JSON config from %s: %v", path, err)
		return
	}

	if root.Global != nil && root.Global.LogLevel != nil && !Cfg.LogLevelCmdline {
		SetLogLevel(*root.Global.LogLevel)
		Noticef("Log level set to %d", LogLevel())
	}

	if root.Global != nil && root.Global.StaleClientSweepIntervalSeconds != nil &&
		*root.Global.StaleClientSweepIntervalSeconds > 0 {
		staleClientSweepInterval = time.Duration(*root.Global.StaleClientSweepIntervalSeconds) * time.Second
	}

	for name, ifaceObj := range root.Interfaces {
		if err := parseInterfaceJSON(name, ifaceObj); err != nil {
			Warnf("%v", err)
		}
	}
}

// closeInterface tears down and forgets an interface that is no longer
// present in the config.
func closeInterface(i *Interface) {
	delete(interfaces, i.Name)

	arpSetup(i, false)
	dhcpv4Setup(i, false)
}

// reloadServices (re)enables or tears down the two relay services for
// one interface based on its current link state.
func reloadServices(i *Interface) {
	if i.Running {
		Debugf("Enabling services with %s running", i.Ifname)
		_ = arpSetup(i, i.ARP != ModeDisabled)
		_ = dhcpv4Setup(i, i.DHCPv4 != ModeDisabled)
	} else {
		Debugf("Disabling services with %s not running", i.Ifname)
		_ = arpSetup(i, false)
		_ = dhcpv4Setup(i, false)
	}
}

func disableServices(i *Interface) {
	_ = arpSetup(i, false)
	_ = dhcpv4Setup(i, false)
}

// Reload re-reads the config file from scratch and applies it, including the
// "disable master relay if there is no slave" logic. Must run on the Engine goroutine.
func Reload() {
	for _, i := range interfaces {
		setInterfaceDefaults(i)
		i.Inuse = false
	}

	loadConfigJSON(Cfg.ConfigFile)

	// Only after config.json has been loaded (so a configured
	// global.stale_client_sweep_interval_seconds already took effect) - see
	// scheduleMirrorSweep's doc comment.
	scheduleMirrorSweep()

	anyDHCPv4Slave, anyARPSlave := false, false
	for _, i := range interfaces {
		if i.Master {
			continue
		}
		if i.DHCPv4 == ModeRelay {
			anyDHCPv4Slave = true
		}
		if i.ARP == ModeRelay {
			anyARPSlave = true
		}
	}

	for _, i := range interfaces {
		if !i.Master {
			continue
		}
		if i.DHCPv4 == ModeRelay && !anyDHCPv4Slave {
			i.DHCPv4 = ModeDisabled
		}
		if i.ARP == ModeRelay && !anyARPSlave {
			i.ARP = ModeDisabled
		}
	}

	// Only drop interfaces that are no longer present in the reloaded
	// config at all; one that is merely not IFF_RUNNING yet must stay
	// registered so a later link-up netlink event can find and enable it.
	for _, i := range copyIfaceList() {
		if i.Inuse {
			reloadServices(i)
		} else {
			closeInterface(i)
		}
	}
}

func copyIfaceList() []*Interface {
	out := make([]*Interface, 0, len(interfaces))
	for _, i := range interfaces {
		out = append(out, i)
	}
	return out
}

// netip is referenced here only to keep the import list identical across
// platforms; silence the unused warning if no other file uses it yet.
var _ = netip.Addr{}