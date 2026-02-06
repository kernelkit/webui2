package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kernelkit/infix-webui/internal/restconf"
)

// yangInt64 unmarshals a YANG numeric value that RESTCONF encodes as a
// JSON string (e.g. "1024000") or, occasionally, as a bare number.
type yangInt64 int64

func (y *yangInt64) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		*y = yangInt64(v)
		return nil
	}
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*y = yangInt64(v)
	return nil
}

// yangBool unmarshals a YANG boolean that RESTCONF may encode as a
// JSON string ("true"/"false") or as a bare boolean.
type yangBool bool

func (y *yangBool) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		v, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		*y = yangBool(v)
		return nil
	}
	var v bool
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*y = yangBool(v)
	return nil
}

// yangFloat64 unmarshals a YANG decimal value that RESTCONF may encode
// as a JSON string (e.g. "0.12") or as a bare number.
type yangFloat64 float64

func (y *yangFloat64) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		*y = yangFloat64(v)
		return nil
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*y = yangFloat64(v)
	return nil
}

// RESTCONF JSON structures for ietf-system:system-state.

type systemStateWrapper struct {
	SystemState systemState `json:"ietf-system:system-state"`
}

type systemState struct {
	Platform platform      `json:"platform"`
	Clock    clock         `json:"clock"`
	Software software      `json:"infix-system:software"`
	Resource resourceUsage `json:"infix-system:resource-usage"`
}

type platform struct {
	OSName    string `json:"os-name"`
	OSVersion string `json:"os-version"`
	Machine   string `json:"machine"`
}

type clock struct {
	BootDatetime    string `json:"boot-datetime"`
	CurrentDatetime string `json:"current-datetime"`
}

type software struct {
	Booted string         `json:"booted"`
	Slot   []softwareSlot `json:"slot"`
}

type softwareSlot struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type resourceUsage struct {
	Memory      memoryInfo     `json:"memory"`
	LoadAverage loadAverage    `json:"load-average"`
	Filesystem  []filesystemFS `json:"filesystem"`
}

type memoryInfo struct {
	Total     yangInt64 `json:"total"`
	Free      yangInt64 `json:"free"`
	Available yangInt64 `json:"available"`
}

type loadAverage struct {
	Load1min  yangFloat64 `json:"load-1min"`
	Load5min  yangFloat64 `json:"load-5min"`
	Load15min yangFloat64 `json:"load-15min"`
}

type filesystemFS struct {
	MountPoint string    `json:"mount-point"`
	Size       yangInt64 `json:"size"`
	Used       yangInt64 `json:"used"`
	Available  yangInt64 `json:"available"`
}

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
	Statistics  *struct {
		InOctets  yangInt64 `json:"in-octets"`
		OutOctets yangInt64 `json:"out-octets"`
	} `json:"statistics"`
	Ethernet *struct {
		Speed  string `json:"speed"`
		Duplex string `json:"duplex"`
	} `json:"ieee802-ethernet-interface:ethernet"`
	BridgePort *bridgePortJSON `json:"infix-interfaces:bridge-port"`
	WiFi       *wifiJSON       `json:"infix-interfaces:wifi"`
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
		Station []struct{} `json:"station"`
	} `json:"stations"`
}

type wifiStationJSON struct {
	SSID           string `json:"ssid"`
	SignalStrength *int   `json:"signal-strength"`
}

type ipCfg struct {
	Address []ipAddr `json:"address"`
}

type ipAddr struct {
	IP           string    `json:"ip"`
	PrefixLength yangInt64 `json:"prefix-length"`
	Origin       string    `json:"origin"`
}

// RESTCONF JSON structures for ietf-hardware:hardware.

type hardwareWrapper struct {
	Hardware struct {
		Component []hwComponentJSON `json:"component"`
	} `json:"ietf-hardware:hardware"`
}

type hwComponentJSON struct {
	Name        string `json:"name"`
	Class       string `json:"class"`
	Description string `json:"description"`
	Parent      string `json:"parent"`
	MfgName     string `json:"mfg-name"`
	ModelName   string `json:"model-name"`
	SerialNum   string `json:"serial-num"`
	HardwareRev string `json:"hardware-rev"`
	PhysAddress string `json:"infix-hardware:phys-address"`
	SensorData  *struct {
		ValueType  string    `json:"value-type"`
		Value      yangInt64 `json:"value"`
		ValueScale string    `json:"value-scale"`
		OperStatus string    `json:"oper-status"`
	} `json:"sensor-data"`
	State *struct {
		AdminState string `json:"admin-state"`
		OperState  string `json:"oper-state"`
	} `json:"state"`
}

// Template data structures.

type dashboardData struct {
	Username   string
	Hostname   string
	OSName     string
	OSVersion  string
	Machine    string
	Firmware   string
	Uptime     string
	MemTotal   int64
	MemUsed    int64
	MemPercent int
	Load1      string
	Load5      string
	Load15     string
	Disks      []diskEntry
	Interfaces []ifaceEntry
	Board      boardInfo
	Sensors    []sensorEntry
	Error      string
}

type boardInfo struct {
	Model       string
	Manufacturer string
	SerialNum   string
	HardwareRev string
	BaseMAC     string
}

type sensorEntry struct {
	Name  string
	Value string
	Type  string // "temperature", "fan", "voltage", etc.
}

type diskEntry struct {
	Mount     string
	Size      string
	Used      string
	Available string
	Percent   int
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

// DashboardHandler serves the main dashboard page.
type DashboardHandler struct {
	Template *template.Template
	RC       *restconf.Client
}

// Index renders the dashboard (GET /).
func (h *DashboardHandler) Index(w http.ResponseWriter, r *http.Request) {
	creds := restconf.CredentialsFromContext(r.Context())
	data := dashboardData{Username: creds.Username}

	var state systemStateWrapper
	if err := h.RC.Get(r.Context(), "/data/ietf-system:system-state", &state); err != nil {
		log.Printf("restconf system-state: %v", err)
		data.Error = "Could not fetch system information"
	} else {
		ss := state.SystemState
		data.OSName = ss.Platform.OSName
		data.OSVersion = ss.Platform.OSVersion
		data.Machine = ss.Platform.Machine
		data.Firmware = firmwareVersion(ss.Software)
		data.Uptime = computeUptime(ss.Clock.BootDatetime, ss.Clock.CurrentDatetime)

		total := int64(ss.Resource.Memory.Total)
		avail := int64(ss.Resource.Memory.Available)
		data.MemTotal = total / 1024 // KiB → MiB
		data.MemUsed = (total - avail) / 1024
		if total > 0 {
			data.MemPercent = int(float64(total-avail) / float64(total) * 100)
		}

		la := ss.Resource.LoadAverage
		data.Load1 = strconv.FormatFloat(float64(la.Load1min), 'f', 2, 64)
		data.Load5 = strconv.FormatFloat(float64(la.Load5min), 'f', 2, 64)
		data.Load15 = strconv.FormatFloat(float64(la.Load15min), 'f', 2, 64)

		for _, fs := range ss.Resource.Filesystem {
			size := int64(fs.Size)
			used := int64(fs.Used)
			pct := 0
			if size > 0 {
				pct = int(float64(used) / float64(size) * 100)
			}
			data.Disks = append(data.Disks, diskEntry{
				Mount:     fs.MountPoint,
				Size:      humanKiB(size),
				Used:      humanKiB(used),
				Available: humanKiB(int64(fs.Available)),
				Percent:   pct,
			})
		}
	}

	// Fetch interface status.
	var ifaces interfacesWrapper
	if err := h.RC.Get(r.Context(), "/data/ietf-interfaces:interfaces", &ifaces); err != nil {
		log.Printf("restconf interfaces: %v", err)
	} else {
		data.Interfaces = buildIfaceList(ifaces.Interfaces.Interface)
	}

	// Fetch hardware components (board info + sensors).
	var hw hardwareWrapper
	if err := h.RC.Get(r.Context(), "/data/ietf-hardware:hardware", &hw); err != nil {
		log.Printf("restconf hardware: %v", err)
	} else {
		for _, c := range hw.Hardware.Component {
			class := shortClass(c.Class)
			if class == "chassis" {
				data.Board = boardInfo{
					Model:        c.ModelName,
					Manufacturer: c.MfgName,
					SerialNum:    c.SerialNum,
					HardwareRev:  c.HardwareRev,
					BaseMAC:      c.PhysAddress,
				}
			}
			if c.SensorData != nil && c.SensorData.OperStatus == "ok" {
				data.Sensors = append(data.Sensors, sensorEntry{
					Name:  c.Name,
					Value: formatSensor(c.SensorData.ValueType, int64(c.SensorData.Value), c.SensorData.ValueScale),
					Type:  c.SensorData.ValueType,
				})
			}
		}
	}

	// Also fetch hostname from config.
	var sysConf struct {
		System struct {
			Hostname string `json:"hostname"`
		} `json:"ietf-system:system"`
	}
	if err := h.RC.Get(r.Context(), "/data/ietf-system:system", &sysConf); err == nil {
		data.Hostname = sysConf.System.Hostname
	}

	tmplName := "dashboard.html"
	if r.Header.Get("HX-Request") == "true" {
		tmplName = "content"
	}
	if err := h.Template.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// firmwareVersion returns the version string for the booted software slot.
func firmwareVersion(sw software) string {
	for _, slot := range sw.Slot {
		if slot.Name == sw.Booted {
			return slot.Version
		}
	}
	return ""
}

// computeUptime returns a human-readable uptime string from RFC3339 timestamps.
func computeUptime(boot, now string) string {
	bootT, err := time.Parse(time.RFC3339, boot)
	if err != nil {
		return ""
	}
	nowT, err := time.Parse(time.RFC3339, now)
	if err != nil {
		nowT = time.Now()
	}

	d := nowT.Sub(bootT)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

// shortClass strips the YANG module prefix from a hardware class identity.
func shortClass(full string) string {
	if i := strings.LastIndex(full, ":"); i >= 0 {
		return full[i+1:]
	}
	return full
}

// formatSensor converts a raw sensor value to a human-readable string,
// matching the formatting used by cli_pretty.
func formatSensor(valueType string, value int64, scale string) string {
	v := float64(value)
	switch scale {
	case "milli":
		v /= 1000
	case "micro":
		v /= 1000000
	}
	switch valueType {
	case "celsius":
		return fmt.Sprintf("%.1f\u00b0C", v)
	case "rpm":
		return fmt.Sprintf("%.0f RPM", v)
	case "volts-DC":
		return fmt.Sprintf("%.2f VDC", v)
	case "amperes":
		return fmt.Sprintf("%.2f A", v)
	case "watts":
		return fmt.Sprintf("%.2f W", v)
	default:
		return fmt.Sprintf("%.1f", v)
	}
}

// prettyIfType converts a YANG interface type identity to the display
// name used by the Infix CLI (cli_pretty).
func prettyIfType(full string) string {
	// Map of YANG identity suffixes to cli_pretty display names.
	pretty := map[string]string{
		// infix-if-type identities
		"bridge":    "bridge",
		"dummy":     "dummy",
		"ethernet":  "ethernet",
		"gre":       "gre",
		"gretap":    "gretap",
		"vxlan":     "vxlan",
		"wireguard": "wireguard",
		"lag":       "lag",
		"loopback":  "loopback",
		"veth":      "veth",
		"vlan":      "vlan",
		"wifi":      "wifi",
		"other":     "other",
		// iana-if-type identities
		"ethernetCsmacd":  "ethernet",
		"softwareLoopback": "loopback",
		"l2vlan":           "vlan",
		"ieee8023adLag":    "lag",
		"ieee80211":        "wifi",
		"ilan":             "veth",
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
	// Index by name and group bridge children.
	byName := map[string]*ifaceJSON{}
	children := map[string][]string{} // bridge name → member names
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
			continue // rendered under its parent
		}

		result = append(result, makeIfaceEntry(iface, ""))

		// Append bridge members with tree prefixes.
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
			// Show STP state for bridge members.
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

	// WiFi detail string matching cli_pretty.
	if iface.WiFi != nil {
		if ap := iface.WiFi.AccessPoint; ap != nil {
			n := len(ap.Stations.Station)
			e.Detail = fmt.Sprintf("AP, ssid: %s, stations: %d", ap.SSID, n)
		} else if st := iface.WiFi.Station; st != nil {
			e.Detail = fmt.Sprintf("Station, ssid: %s", st.SSID)
		}
	}

	return e
}

// humanBytes converts bytes to a human-readable string (B, KiB, MiB, GiB, TiB).
func humanBytes(b int64) string {
	v := float64(b)
	for _, unit := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if v < 1024 || unit == "TiB" {
			if v == math.Trunc(v) {
				return fmt.Sprintf("%.0f %s", v, unit)
			}
			return fmt.Sprintf("%.1f %s", v, unit)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1f PiB", v)
}

// humanKiB converts KiB to a human-readable string (K, M, G, T).
func humanKiB(kib int64) string {
	v := float64(kib)
	for _, unit := range []string{"K", "M", "G", "T"} {
		if v < 1024 || unit == "T" {
			if v == math.Trunc(v) {
				return fmt.Sprintf("%.0f%s", v, unit)
			}
			return fmt.Sprintf("%.1f%s", v, unit)
		}
		v /= 1024
	}
	return fmt.Sprintf("%.1fP", v)
}
