package handlers

import (
	"context"
	"sync"

	"github.com/kernelkit/infix-webui/internal/restconf"
)

// Capabilities tracks which optional features are available on the device.
// Each field is set to true if the corresponding RESTCONF probe succeeds.
type Capabilities struct {
	WiFi       bool
	Containers bool
	OSPF       bool
	WireGuard  bool
	DHCPServer bool
	NTP        bool
	LLDP       bool
}

// DetectCapabilities probes RESTCONF endpoints in parallel to determine
// which features are available on the device. Any error (including 404)
// results in the corresponding capability being set to false.
func DetectCapabilities(ctx context.Context, rc restconf.Fetcher) *Capabilities {
	caps := &Capabilities{}
	var wg sync.WaitGroup

	probe := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	// WiFi: check for hardware components with wifi-radio class
	probe(func() {
		var hw struct {
			Hardware struct {
				Component []struct {
					Class string `json:"class"`
				} `json:"component"`
			} `json:"ietf-hardware:hardware"`
		}
		if err := rc.Get(ctx, "ietf-hardware:hardware", &hw); err != nil {
			return
		}
		for _, c := range hw.Hardware.Component {
			if c.Class == "infix-hardware:wifi-radio" {
				caps.WiFi = true
				return
			}
		}
	})

	// Containers: path exists → feature available
	probe(func() {
		if _, err := rc.GetRaw(ctx, "infix-containers:containers"); err == nil {
			caps.Containers = true
		}
	})

	// OSPF: check for ospfv2 control-plane protocol
	probe(func() {
		var routing struct {
			Routing struct {
				CPP struct {
					Protocol []struct {
						Type string `json:"type"`
					} `json:"control-plane-protocol"`
				} `json:"control-plane-protocols"`
			} `json:"ietf-routing:routing"`
		}
		if err := rc.Get(ctx, "ietf-routing:routing/control-plane-protocols", &routing); err != nil {
			return
		}
		for _, p := range routing.Routing.CPP.Protocol {
			if p.Type == "ietf-ospf:ospfv2" || p.Type == "ospfv2" {
				caps.OSPF = true
				return
			}
		}
	})

	// WireGuard: check for wireguard interface type
	probe(func() {
		var ifaces struct {
			Interfaces struct {
				Interface []struct {
					Type string `json:"type"`
				} `json:"interface"`
			} `json:"ietf-interfaces:interfaces"`
		}
		if err := rc.Get(ctx, "ietf-interfaces:interfaces", &ifaces); err != nil {
			return
		}
		for _, iface := range ifaces.Interfaces.Interface {
			if iface.Type == "infix-if-type:wireguard" {
				caps.WireGuard = true
				return
			}
		}
	})

	// DHCPServer: path exists → feature available
	probe(func() {
		if _, err := rc.GetRaw(ctx, "infix-dhcp-server:dhcp-server"); err == nil {
			caps.DHCPServer = true
		}
	})

	// NTP: path exists → feature available
	probe(func() {
		if _, err := rc.GetRaw(ctx, "ietf-ntp:ntp"); err == nil {
			caps.NTP = true
		}
	})

	// LLDP: path exists → feature available
	probe(func() {
		if _, err := rc.GetRaw(ctx, "ieee802-dot1ab-lldp:lldp"); err == nil {
			caps.LLDP = true
		}
	})

	wg.Wait()
	return caps
}
