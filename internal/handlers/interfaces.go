package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/kernelkit/infix-webui/internal/restconf"
)

// RESTCONF JSON structures for ietf-interfaces:interfaces.

type interfacesWrapper struct {
	Interfaces struct {
		Interface []ifaceJSON `json:"interface"`
	} `json:"ietf-interfaces:interfaces"`
}

type ifaceJSON struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	OperStatus  string `json:"oper-status"`
	PhysAddress string `json:"phys-address"`
	IfIndex     int    `json:"if-index"`
	IPv4        *ipCfg `json:"ietf-ip:ipv4"`
	IPv6        *ipCfg `json:"ietf-ip:ipv6"`
	Statistics *ifaceStats   `json:"statistics"`
	Ethernet   *ethernetJSON `json:"ieee802-ethernet-interface:ethernet"`
	BridgePort *bridgePortJSON  `json:"infix-interfaces:bridge-port"`
	WiFi       *wifiJSON        `json:"infix-interfaces:wifi"`
	WireGuard  *wireGuardJSON   `json:"infix-interfaces:wireguard"`
}

type bridgePortJSON struct {
	Bridge string `json:"bridge"`
	STP    *struct {
		CIST *struct {
			State string `json:"state"`
		} `json:"cist"`
	} `json:"stp"`
}

type wifiJSON struct {
	AccessPoint *wifiAPJSON      `json:"access-point"`
	Station     *wifiStationJSON `json:"station"`
}

type wifiAPJSON struct {
	SSID     string `json:"ssid"`
	Stations struct {
		Station []wifiStaJSON `json:"station"`
	} `json:"stations"`
}

type wifiStaJSON struct {
	MACAddress    string    `json:"mac-address"`
	SignalStrength *int     `json:"signal-strength"`
	ConnectedTime  yangInt64 `json:"connected-time"`
	RxPackets     yangInt64 `json:"rx-packets"`
	TxPackets     yangInt64 `json:"tx-packets"`
	RxBytes       yangInt64 `json:"rx-bytes"`
	TxBytes       yangInt64 `json:"tx-bytes"`
	RxSpeed       yangInt64 `json:"rx-speed"`
	TxSpeed       yangInt64 `json:"tx-speed"`
}

type wifiStationJSON struct {
	SSID           string `json:"ssid"`
	SignalStrength *int   `json:"signal-strength"`
}

type wireGuardJSON struct {
	PeerStatus *struct {
		Peer []wgPeerJSON `json:"peer"`
	} `json:"peer-status"`
}

type wgPeerJSON struct {
	PublicKey        string `json:"public-key"`
	ConnectionStatus string `json:"connection-status"`
	EndpointAddress  string `json:"endpoint-address"`
	EndpointPort     int    `json:"endpoint-port"`
	LatestHandshake  string `json:"latest-handshake"`
	Transfer         *struct {
		TxBytes yangInt64 `json:"tx-bytes"`
		RxBytes yangInt64 `json:"rx-bytes"`
	} `json:"transfer"`
}

type ipCfg struct {
	Address []ipAddr `json:"address"`
	MTU     int      `json:"mtu"`
}

type ipAddr struct {
	IP           string    `json:"ip"`
	PrefixLength yangInt64 `json:"prefix-length"`
	Origin       string    `json:"origin"`
}

type ifaceStats struct {
	InOctets        yangInt64 `json:"in-octets"`
	OutOctets       yangInt64 `json:"out-octets"`
	InUnicastPkts   yangInt64 `json:"in-unicast-pkts"`
	InBroadcastPkts yangInt64 `json:"in-broadcast-pkts"`
	InMulticastPkts yangInt64 `json:"in-multicast-pkts"`
	InDiscards      yangInt64 `json:"in-discards"`
	InErrors        yangInt64 `json:"in-errors"`
	OutUnicastPkts  yangInt64 `json:"out-unicast-pkts"`
	OutBroadcastPkts yangInt64 `json:"out-broadcast-pkts"`
	OutMulticastPkts yangInt64 `json:"out-multicast-pkts"`
	OutDiscards     yangInt64 `json:"out-discards"`
	OutErrors       yangInt64 `json:"out-errors"`
}

type ethernetJSON struct {
	Speed           string `json:"speed"`
	Duplex          string `json:"duplex"`
	AutoNegotiation *struct {
		Enable bool `json:"enable"`
	} `json:"auto-negotiation"`
	Statistics *struct {
		Frame *ethFrameStats `json:"frame"`
	} `json:"statistics"`
}

type ethFrameStats struct {
	InTotalPkts            yangInt64 `json:"in-total-pkts"`
	InTotalOctets          yangInt64 `json:"in-total-octets"`
	InGoodPkts             yangInt64 `json:"in-good-pkts"`
	InGoodOctets           yangInt64 `json:"in-good-octets"`
	InBroadcast            yangInt64 `json:"in-broadcast"`
	InMulticast            yangInt64 `json:"in-multicast"`
	InErrorFCS             yangInt64 `json:"in-error-fcs"`
	InErrorUndersize       yangInt64 `json:"in-error-undersize"`
	InErrorOversize        yangInt64 `json:"in-error-oversize"`
	InErrorMACInternal     yangInt64 `json:"in-error-mac-internal"`
	OutTotalPkts           yangInt64 `json:"out-total-pkts"`
	OutTotalOctets         yangInt64 `json:"out-total-octets"`
	OutGoodPkts            yangInt64 `json:"out-good-pkts"`
	OutGoodOctets          yangInt64 `json:"out-good-octets"`
	OutBroadcast           yangInt64 `json:"out-broadcast"`
	OutMulticast           yangInt64 `json:"out-multicast"`
}

// Template data structures.

type interfacesData struct {
	Username   string
	Interfaces []ifaceEntry
	Error      string
}

type ifaceEntry struct {
	Indent    string // tree prefix for bridge/LAG members
	Name      string
	Type      string
	Status    string
	StatusUp  bool
	PhysAddr  string
	Addresses []addrEntry
	Detail    string // extra info: wifi AP, wireguard peers, etc.
	RxBytes   string
	TxBytes   string
}

type addrEntry struct {
	Address string
	Origin  string
}

// InterfacesHandler serves the interfaces pages.
type InterfacesHandler struct {
	Template         *template.Template
	DetailTemplate   *template.Template
	CountersTemplate *template.Template
	RC               *restconf.Client
}

// Overview renders the interfaces page (GET /interfaces).
func (h *InterfacesHandler) Overview(w http.ResponseWriter, r *http.Request) {
	creds := restconf.CredentialsFromContext(r.Context())
	data := interfacesData{Username: creds.Username}

	var ifaces interfacesWrapper
	if err := h.RC.Get(r.Context(), "/data/ietf-interfaces:interfaces", &ifaces); err != nil {
		log.Printf("restconf interfaces: %v", err)
		data.Error = "Could not fetch interface information"
	} else {
		data.Interfaces = buildIfaceList(ifaces.Interfaces.Interface)
	}

	tmplName := "interfaces.html"
	if r.Header.Get("HX-Request") == "true" {
		tmplName = "content"
	}
	if err := h.Template.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// prettyIfType converts a YANG interface type identity to the display
// name used by the Infix CLI (cli_pretty).
func prettyIfType(full string) string {
	pretty := map[string]string{
		"bridge":            "bridge",
		"dummy":             "dummy",
		"ethernet":          "ethernet",
		"gre":               "gre",
		"gretap":            "gretap",
		"vxlan":             "vxlan",
		"wireguard":         "wireguard",
		"lag":               "lag",
		"loopback":          "loopback",
		"veth":              "veth",
		"vlan":              "vlan",
		"wifi":              "wifi",
		"other":             "other",
		"ethernetCsmacd":    "ethernet",
		"softwareLoopback":  "loopback",
		"l2vlan":            "vlan",
		"ieee8023adLag":     "lag",
		"ieee80211":         "wifi",
		"ilan":              "veth",
	}

	if i := strings.LastIndex(full, ":"); i >= 0 {
		full = full[i+1:]
	}
	if name, ok := pretty[full]; ok {
		return name
	}
	return full
}

// buildIfaceList converts raw RESTCONF interface data into a flat,
// hierarchically ordered display list matching the cli_pretty style.
// Bridge members are grouped under their parent with tree indicators.
func buildIfaceList(raw []ifaceJSON) []ifaceEntry {
	byName := map[string]*ifaceJSON{}
	children := map[string][]string{}
	childSet := map[string]bool{}

	for i := range raw {
		iface := &raw[i]
		byName[iface.Name] = iface
		if iface.BridgePort != nil && iface.BridgePort.Bridge != "" {
			parent := iface.BridgePort.Bridge
			children[parent] = append(children[parent], iface.Name)
			childSet[iface.Name] = true
		}
	}

	var result []ifaceEntry

	for _, iface := range raw {
		if childSet[iface.Name] {
			continue
		}

		result = append(result, makeIfaceEntry(iface, ""))

		members := children[iface.Name]
		for i, childName := range members {
			child, ok := byName[childName]
			if !ok {
				continue
			}
			prefix := "\u251c\u00a0" // ├
			if i == len(members)-1 {
				prefix = "\u2514\u00a0" // └
			}
			e := makeIfaceEntry(*child, prefix)
			if child.BridgePort != nil && child.BridgePort.STP != nil &&
				child.BridgePort.STP.CIST != nil && child.BridgePort.STP.CIST.State != "" {
				e.Status = child.BridgePort.STP.CIST.State
				e.StatusUp = e.Status == "forwarding"
			}
			result = append(result, e)
		}
	}

	return result
}

func makeIfaceEntry(iface ifaceJSON, indent string) ifaceEntry {
	e := ifaceEntry{
		Indent:   indent,
		Name:     iface.Name,
		Type:     prettyIfType(iface.Type),
		Status:   iface.OperStatus,
		StatusUp: iface.OperStatus == "up",
		PhysAddr: iface.PhysAddress,
	}

	if iface.Statistics != nil {
		e.RxBytes = humanBytes(int64(iface.Statistics.InOctets))
		e.TxBytes = humanBytes(int64(iface.Statistics.OutOctets))
	}

	if iface.IPv4 != nil {
		for _, a := range iface.IPv4.Address {
			e.Addresses = append(e.Addresses, addrEntry{
				Address: fmt.Sprintf("%s/%d", a.IP, int(a.PrefixLength)),
				Origin:  a.Origin,
			})
		}
	}
	if iface.IPv6 != nil {
		for _, a := range iface.IPv6.Address {
			e.Addresses = append(e.Addresses, addrEntry{
				Address: fmt.Sprintf("%s/%d", a.IP, int(a.PrefixLength)),
				Origin:  a.Origin,
			})
		}
	}

	if iface.WiFi != nil {
		if ap := iface.WiFi.AccessPoint; ap != nil {
			n := len(ap.Stations.Station)
			e.Detail = fmt.Sprintf("AP, ssid: %s, stations: %d", ap.SSID, n)
		} else if st := iface.WiFi.Station; st != nil {
			e.Detail = fmt.Sprintf("Station, ssid: %s", st.SSID)
		}
	}

	if wg := iface.WireGuard; wg != nil && wg.PeerStatus != nil {
		total := len(wg.PeerStatus.Peer)
		up := 0
		for _, p := range wg.PeerStatus.Peer {
			if p.ConnectionStatus == "up" {
				up++
			}
		}
		e.Detail = fmt.Sprintf("%d peers (%d up)", total, up)
	}

	return e
}

// Template data for the interface detail page.
type ifaceDetailData struct {
	Username  string
	Name      string
	Type      string
	Status    string
	StatusUp  bool
	PhysAddr  string
	IfIndex   int
	MTU       int
	Speed     string
	Duplex    string
	AutoNeg   string
	Addresses     []addrEntry
	Detail        string
	Counters      ifaceCounters
	EthFrameStats []kvEntry
	WGPeers       []wgPeerEntry
	WiFiStations  []wifiStaEntry
}

type ifaceCounters struct {
	RxBytes     string
	RxUnicast   string
	RxBroadcast string
	RxMulticast string
	RxDiscards  string
	RxErrors    string
	TxBytes     string
	TxUnicast   string
	TxBroadcast string
	TxMulticast string
	TxDiscards  string
	TxErrors    string
}

type kvEntry struct {
	Key   string
	Value string
}

type wgPeerEntry struct {
	PublicKey  string
	Status    string
	StatusUp  bool
	Endpoint  string
	Handshake string
	TxBytes   string
	RxBytes   string
}

type wifiStaEntry struct {
	MAC       string
	Signal    string
	SignalCSS string // "excellent", "good", "poor", "bad"
	Time      string
	RxPkts    string
	TxPkts    string
	RxBytes   string
	TxBytes   string
	RxSpeed   string
	TxSpeed   string
}

// fetchInterface retrieves a single interface by name from RESTCONF.
func (h *InterfacesHandler) fetchInterface(r *http.Request, name string) (*ifaceJSON, error) {
	var all interfacesWrapper
	if err := h.RC.Get(r.Context(), "/data/ietf-interfaces:interfaces", &all); err != nil {
		return nil, err
	}
	for i := range all.Interfaces.Interface {
		if all.Interfaces.Interface[i].Name == name {
			return &all.Interfaces.Interface[i], nil
		}
	}
	return nil, fmt.Errorf("interface %q not found", name)
}

// buildDetailData converts raw RESTCONF interface data to template data.
func buildDetailData(username string, iface *ifaceJSON) ifaceDetailData {
	d := ifaceDetailData{
		Username: username,
		Name:     iface.Name,
		Type:     prettyIfType(iface.Type),
		Status:   iface.OperStatus,
		StatusUp: iface.OperStatus == "up",
		PhysAddr: iface.PhysAddress,
		IfIndex:  iface.IfIndex,
	}

	if iface.IPv4 != nil {
		if iface.IPv4.MTU > 0 {
			d.MTU = iface.IPv4.MTU
		}
		for _, a := range iface.IPv4.Address {
			d.Addresses = append(d.Addresses, addrEntry{
				Address: fmt.Sprintf("%s/%d", a.IP, int(a.PrefixLength)),
				Origin:  a.Origin,
			})
		}
	}
	if iface.IPv6 != nil {
		for _, a := range iface.IPv6.Address {
			d.Addresses = append(d.Addresses, addrEntry{
				Address: fmt.Sprintf("%s/%d", a.IP, int(a.PrefixLength)),
				Origin:  a.Origin,
			})
		}
	}

	if iface.Ethernet != nil {
		d.Speed = prettySpeed(iface.Ethernet.Speed)
		d.Duplex = iface.Ethernet.Duplex
		if iface.Ethernet.AutoNegotiation != nil {
			if iface.Ethernet.AutoNegotiation.Enable {
				d.AutoNeg = "on"
			} else {
				d.AutoNeg = "off"
			}
		}
		if iface.Ethernet.Statistics != nil && iface.Ethernet.Statistics.Frame != nil {
			d.EthFrameStats = buildEthFrameStats(iface.Ethernet.Statistics.Frame)
		}
	}

	if iface.Statistics != nil {
		d.Counters = buildCounters(iface.Statistics)
	}

	if iface.WiFi != nil {
		if ap := iface.WiFi.AccessPoint; ap != nil {
			n := len(ap.Stations.Station)
			d.Detail = fmt.Sprintf("AP, ssid: %s, stations: %d", ap.SSID, n)
			for _, s := range ap.Stations.Station {
				d.WiFiStations = append(d.WiFiStations, buildWifiStaEntry(s))
			}
		} else if st := iface.WiFi.Station; st != nil {
			d.Detail = fmt.Sprintf("Station, ssid: %s", st.SSID)
		}
	}

	if wg := iface.WireGuard; wg != nil && wg.PeerStatus != nil {
		for _, p := range wg.PeerStatus.Peer {
			pe := wgPeerEntry{
				PublicKey: p.PublicKey,
				Status:   p.ConnectionStatus,
				StatusUp: p.ConnectionStatus == "up",
			}
			if p.EndpointAddress != "" {
				pe.Endpoint = fmt.Sprintf("%s:%d", p.EndpointAddress, p.EndpointPort)
			}
			if p.LatestHandshake != "" {
				pe.Handshake = p.LatestHandshake
			}
			if p.Transfer != nil {
				pe.TxBytes = humanBytes(int64(p.Transfer.TxBytes))
				pe.RxBytes = humanBytes(int64(p.Transfer.RxBytes))
			}
			d.WGPeers = append(d.WGPeers, pe)
		}
		total := len(wg.PeerStatus.Peer)
		up := 0
		for _, p := range wg.PeerStatus.Peer {
			if p.ConnectionStatus == "up" {
				up++
			}
		}
		d.Detail = fmt.Sprintf("%d peers (%d up)", total, up)
	}

	return d
}

func buildCounters(s *ifaceStats) ifaceCounters {
	return ifaceCounters{
		RxBytes:     humanBytes(int64(s.InOctets)),
		RxUnicast:   formatCount(int64(s.InUnicastPkts)),
		RxBroadcast: formatCount(int64(s.InBroadcastPkts)),
		RxMulticast: formatCount(int64(s.InMulticastPkts)),
		RxDiscards:  formatCount(int64(s.InDiscards)),
		RxErrors:    formatCount(int64(s.InErrors)),
		TxBytes:     humanBytes(int64(s.OutOctets)),
		TxUnicast:   formatCount(int64(s.OutUnicastPkts)),
		TxBroadcast: formatCount(int64(s.OutBroadcastPkts)),
		TxMulticast: formatCount(int64(s.OutMulticastPkts)),
		TxDiscards:  formatCount(int64(s.OutDiscards)),
		TxErrors:    formatCount(int64(s.OutErrors)),
	}
}

func buildEthFrameStats(f *ethFrameStats) []kvEntry {
	return []kvEntry{
		{"eth-in-frames", formatCount(int64(f.InTotalPkts))},
		{"eth-in-octets", humanBytes(int64(f.InTotalOctets))},
		{"eth-in-good-frames", formatCount(int64(f.InGoodPkts))},
		{"eth-in-good-octets", humanBytes(int64(f.InGoodOctets))},
		{"eth-in-broadcast", formatCount(int64(f.InBroadcast))},
		{"eth-in-multicast", formatCount(int64(f.InMulticast))},
		{"eth-in-fcs-error", formatCount(int64(f.InErrorFCS))},
		{"eth-in-undersize", formatCount(int64(f.InErrorUndersize))},
		{"eth-in-oversize", formatCount(int64(f.InErrorOversize))},
		{"eth-in-mac-error", formatCount(int64(f.InErrorMACInternal))},
		{"eth-out-frames", formatCount(int64(f.OutTotalPkts))},
		{"eth-out-octets", humanBytes(int64(f.OutTotalOctets))},
		{"eth-out-good-frames", formatCount(int64(f.OutGoodPkts))},
		{"eth-out-good-octets", humanBytes(int64(f.OutGoodOctets))},
		{"eth-out-broadcast", formatCount(int64(f.OutBroadcast))},
		{"eth-out-multicast", formatCount(int64(f.OutMulticast))},
	}
}

// prettySpeed converts YANG ethernet speed identities to display strings.
func prettySpeed(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func buildWifiStaEntry(s wifiStaJSON) wifiStaEntry {
	e := wifiStaEntry{
		MAC:     s.MACAddress,
		Time:    formatDuration(int64(s.ConnectedTime)),
		RxPkts:  formatCount(int64(s.RxPackets)),
		TxPkts:  formatCount(int64(s.TxPackets)),
		RxBytes: humanBytes(int64(s.RxBytes)),
		TxBytes: humanBytes(int64(s.TxBytes)),
		RxSpeed: fmt.Sprintf("%.1f Mbps", float64(s.RxSpeed)/10),
		TxSpeed: fmt.Sprintf("%.1f Mbps", float64(s.TxSpeed)/10),
	}
	if s.SignalStrength != nil {
		sig := *s.SignalStrength
		e.Signal = fmt.Sprintf("%d dBm", sig)
		switch {
		case sig >= -50:
			e.SignalCSS = "excellent"
		case sig >= -60:
			e.SignalCSS = "good"
		case sig >= -70:
			e.SignalCSS = "poor"
		default:
			e.SignalCSS = "bad"
		}
	}
	return e
}

func formatDuration(secs int64) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("%dm %ds", secs/60, secs%60)
	}
	h := secs / 3600
	m := (secs % 3600) / 60
	return fmt.Sprintf("%dh %dm", h, m)
}

// formatCount formats a packet/frame count with thousand separators.
func formatCount(n int64) string {
	if n == 0 {
		return "0"
	}
	s := fmt.Sprintf("%d", n)
	// Insert thousand separators from the right.
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// Detail renders the interface detail page (GET /interfaces/{name}).
func (h *InterfacesHandler) Detail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	creds := restconf.CredentialsFromContext(r.Context())

	iface, err := h.fetchInterface(r, name)
	if err != nil {
		log.Printf("restconf interface %s: %v", name, err)
		http.Error(w, "Interface not found", http.StatusNotFound)
		return
	}

	data := buildDetailData(creds.Username, iface)

	tmplName := "iface-detail.html"
	if r.Header.Get("HX-Request") == "true" {
		tmplName = "content"
	}
	if err := h.DetailTemplate.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Counters renders the counters fragment for htmx polling (GET /interfaces/{name}/counters).
func (h *InterfacesHandler) Counters(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	creds := restconf.CredentialsFromContext(r.Context())

	iface, err := h.fetchInterface(r, name)
	if err != nil {
		log.Printf("restconf interface %s counters: %v", name, err)
		http.Error(w, "Interface not found", http.StatusNotFound)
		return
	}

	data := buildDetailData(creds.Username, iface)

	if err := h.CountersTemplate.ExecuteTemplate(w, "iface-counters", data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
