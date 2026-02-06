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
}

type ipCfg struct {
	Address []ipAddr `json:"address"`
}

type ipAddr struct {
	IP           string    `json:"ip"`
	PrefixLength yangInt64 `json:"prefix-length"`
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
	Error      string
}

type diskEntry struct {
	Mount     string
	Size      string
	Used      string
	Available string
	Percent   int
}

type ifaceEntry struct {
	Name      string
	Type      string
	Status    string
	StatusUp  bool
	Speed     string
	Duplex    string
	PhysAddr  string
	Addresses []string
	RxBytes   string
	TxBytes   string
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
		for _, iface := range ifaces.Interfaces.Interface {
			e := ifaceEntry{
				Name:     iface.Name,
				Type:     shortIfType(iface.Type),
				Status:   iface.OperStatus,
				StatusUp: iface.OperStatus == "up",
				PhysAddr: iface.PhysAddress,
			}
			if iface.Ethernet != nil {
				e.Speed = iface.Ethernet.Speed
				e.Duplex = iface.Ethernet.Duplex
			}
			if iface.Statistics != nil {
				e.RxBytes = humanBytes(int64(iface.Statistics.InOctets))
				e.TxBytes = humanBytes(int64(iface.Statistics.OutOctets))
			}
			if iface.IPv4 != nil {
				for _, a := range iface.IPv4.Address {
					e.Addresses = append(e.Addresses, fmt.Sprintf("%s/%d", a.IP, int(a.PrefixLength)))
				}
			}
			if iface.IPv6 != nil {
				for _, a := range iface.IPv6.Address {
					e.Addresses = append(e.Addresses, fmt.Sprintf("%s/%d", a.IP, int(a.PrefixLength)))
				}
			}
			data.Interfaces = append(data.Interfaces, e)
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

// shortIfType strips the YANG module prefix from interface type identities.
// e.g. "infix-if-type:ethernet" → "ethernet", "iana-if-type:ethernetCsmacd" → "ethernet".
func shortIfType(full string) string {
	if i := strings.LastIndex(full, ":"); i >= 0 {
		full = full[i+1:]
	}
	// Normalise the IANA name to something readable.
	if full == "ethernetCsmacd" {
		return "ethernet"
	}
	if full == "softwareLoopback" {
		return "loopback"
	}
	return full
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
