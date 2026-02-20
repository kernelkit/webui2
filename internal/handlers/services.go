package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kernelkit/infix-webui/internal/restconf"
)

// ─── DHCP types ──────────────────────────────────────────────────────────────

// DHCPLease is a single active DHCP lease.
type DHCPLease struct {
	Address  string
	MAC      string
	Hostname string
	Expires  string // relative or "never"
	ClientID string
}

// DHCPStats holds DHCP packet counters.
type DHCPStats struct {
	InDiscoveries int64
	InRequests    int64
	InReleases    int64
	OutOffers     int64
	OutAcks       int64
	OutNaks       int64
}

// DHCPData is the parsed DHCP server state.
type DHCPData struct {
	Enabled bool
	Leases  []DHCPLease
	Stats   DHCPStats
}

// ─── NTP types ───────────────────────────────────────────────────────────────

// NTPAssoc is a single NTP association/peer.
type NTPAssoc struct {
	Address string
	Stratum int
	RefID   string
	Reach   string // octal string
	Poll    int
	Offset  string // ms
	Delay   string // ms
}

// NTPData is the parsed NTP state.
type NTPData struct {
	Synchronized bool
	Stratum      int
	RefID        string
	Offset       string // ms
	RootDelay    string // ms
	Associations []NTPAssoc
}

// ─── LLDP types ──────────────────────────────────────────────────────────────

// LLDPNeighbor is a remote system seen via LLDP.
type LLDPNeighbor struct {
	LocalPort    string
	ChassisID    string
	SystemName   string
	PortID       string
	PortDesc     string
	SystemDesc   string
	Capabilities string // comma-separated
	MgmtAddress  string
}

// ─── Page data ───────────────────────────────────────────────────────────────

type servicesData struct {
	CsrfToken     string
	PageTitle     string
	ActivePage    string
	Capabilities  *Capabilities
	DHCP          *DHCPData      // nil if not available
	NTP           *NTPData       // nil if not available
	LLDPNeighbors []LLDPNeighbor // nil slice if not available
	Error         string
}

// ─── Handler ─────────────────────────────────────────────────────────────────

// ServicesHandler serves the Services status page.
type ServicesHandler struct {
	Template *template.Template
	RC       *restconf.Client
}

// Overview renders the services page (GET /services).
func (h *ServicesHandler) Overview(w http.ResponseWriter, r *http.Request) {
	data := servicesData{
		CsrfToken:    csrfToken(r.Context()),
		PageTitle:    "Services",
		ActivePage:   "services",
		Capabilities: DetectCapabilities(r.Context(), h.RC),
	}

	// Detach from the request context so RESTCONF calls survive
	// browser connection resets.
	ctx := context.WithoutCancel(r.Context())

	var wg sync.WaitGroup
	wg.Add(3)

	// ── DHCP ──────────────────────────────────────────────────────────────
	go func() {
		defer wg.Done()
		var raw struct {
			DHCP struct {
				Enabled yangBool `json:"enabled"`
				Leases  struct {
					Lease []struct {
						Address  string `json:"address"`
						PhysAddr string `json:"phys-address"`
						Hostname string `json:"hostname"`
						Expires  string `json:"expires"`
						ClientID string `json:"client-id"`
					} `json:"lease"`
				} `json:"leases"`
				Statistics struct {
					OutOffers     yangInt64 `json:"out-offers"`
					OutAcks       yangInt64 `json:"out-acks"`
					OutNaks       yangInt64 `json:"out-naks"`
					InDiscoveries yangInt64 `json:"in-discovers"`
					InRequests    yangInt64 `json:"in-requests"`
					InReleases    yangInt64 `json:"in-releases"`
				} `json:"statistics"`
			} `json:"infix-dhcp-server:dhcp-server"`
		}
		if err := h.RC.Get(ctx, "/data/infix-dhcp-server:dhcp-server", &raw); err != nil {
			log.Printf("restconf dhcp-server: %v", err)
			return
		}
		d := raw.DHCP
		dhcp := &DHCPData{
			Enabled: bool(d.Enabled),
			Stats: DHCPStats{
				InDiscoveries: int64(d.Statistics.InDiscoveries),
				InRequests:    int64(d.Statistics.InRequests),
				InReleases:    int64(d.Statistics.InReleases),
				OutOffers:     int64(d.Statistics.OutOffers),
				OutAcks:       int64(d.Statistics.OutAcks),
				OutNaks:       int64(d.Statistics.OutNaks),
			},
		}
		for _, l := range d.Leases.Lease {
			dhcp.Leases = append(dhcp.Leases, DHCPLease{
				Address:  l.Address,
				MAC:      l.PhysAddr,
				Hostname: l.Hostname,
				Expires:  formatDHCPExpiry(l.Expires),
				ClientID: l.ClientID,
			})
		}
		data.DHCP = dhcp
	}()

	// ── NTP ───────────────────────────────────────────────────────────────
	go func() {
		defer wg.Done()
		var raw struct {
			NTP struct {
				ClockState struct {
					SystemStatus struct {
						ClockState   string          `json:"clock-state"`
						ClockStratum int             `json:"clock-stratum"`
						ClockRefID   json.RawMessage `json:"clock-refid"`
						ClockOffset  yangFloat64     `json:"clock-offset"`
						RootDelay    yangFloat64     `json:"root-delay"`
					} `json:"system-status"`
				} `json:"clock-state"`
				Associations struct {
					Association []struct {
						Address string          `json:"address"`
						Stratum int             `json:"stratum"`
						RefID   json.RawMessage `json:"refid"`
						Reach   uint8           `json:"reach"`
						Poll    int             `json:"poll"`
						Offset  yangFloat64     `json:"offset"`
						Delay   yangFloat64     `json:"delay"`
					} `json:"association"`
				} `json:"associations"`
			} `json:"ietf-ntp:ntp"`
		}
		if err := h.RC.Get(ctx, "/data/ietf-ntp:ntp", &raw); err != nil {
			log.Printf("restconf ntp: %v", err)
			return
		}
		ss := raw.NTP.ClockState.SystemStatus
		synced := strings.Contains(ss.ClockState, "synchronized") &&
			!strings.Contains(ss.ClockState, "unsynchronized")
		ntp := &NTPData{
			Synchronized: synced,
			Stratum:      ss.ClockStratum,
			RefID:        rawJSONString(ss.ClockRefID),
			Offset:       fmt.Sprintf("%.3f ms", float64(ss.ClockOffset)),
			RootDelay:    fmt.Sprintf("%.3f ms", float64(ss.RootDelay)),
		}
		for _, a := range raw.NTP.Associations.Association {
			ntp.Associations = append(ntp.Associations, NTPAssoc{
				Address: a.Address,
				Stratum: a.Stratum,
				RefID:   rawJSONString(a.RefID),
				Reach:   fmt.Sprintf("%o", a.Reach),
				Poll:    a.Poll,
				Offset:  fmt.Sprintf("%.3f ms", float64(a.Offset)),
				Delay:   fmt.Sprintf("%.3f ms", float64(a.Delay)),
			})
		}
		data.NTP = ntp
	}()

	// ── LLDP ──────────────────────────────────────────────────────────────
	go func() {
		defer wg.Done()
		var raw struct {
			LLDP struct {
				Port []struct {
					Name              string `json:"name"`
					DestMACAddress    string `json:"dest-mac-address"`
					RemoteSystemsData []struct {
						ChassisID                 string          `json:"chassis-id"`
						PortID                    string          `json:"port-id"`
						PortDesc                  string          `json:"port-desc"`
						SystemName                string          `json:"system-name"`
						SystemDescription         string          `json:"system-description"`
						SystemCapabilitiesEnabled json.RawMessage `json:"system-capabilities-enabled"`
						ManagementAddress         []struct {
							Address string `json:"address"`
						} `json:"management-address"`
					} `json:"remote-systems-data"`
				} `json:"port"`
			} `json:"ieee802-dot1ab-lldp:lldp"`
		}
		if err := h.RC.Get(ctx, "/data/ieee802-dot1ab-lldp:lldp", &raw); err != nil {
			log.Printf("restconf lldp: %v", err)
			return
		}
		var neighbors []LLDPNeighbor
		for _, port := range raw.LLDP.Port {
			for _, rs := range port.RemoteSystemsData {
				mgmt := ""
				if len(rs.ManagementAddress) > 0 {
					mgmt = rs.ManagementAddress[0].Address
				}
				neighbors = append(neighbors, LLDPNeighbor{
					LocalPort:    port.Name,
					ChassisID:    rs.ChassisID,
					SystemName:   rs.SystemName,
					PortID:       rs.PortID,
					PortDesc:     rs.PortDesc,
					SystemDesc:   rs.SystemDescription,
					Capabilities: parseLLDPCapabilities(rs.SystemCapabilitiesEnabled),
					MgmtAddress:  mgmt,
				})
			}
		}
		data.LLDPNeighbors = neighbors
	}()

	wg.Wait()

	tmplName := "services.html"
	if r.Header.Get("HX-Request") == "true" {
		tmplName = "content"
	}
	if err := h.Template.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// formatDHCPExpiry converts a YANG date-and-time or "never" string to a
// human-readable relative expiry string.
func formatDHCPExpiry(s string) string {
	if s == "" || s == "never" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try without timezone
		t, err = time.Parse("2006-01-02T15:04:05", s)
		if err != nil {
			return s
		}
	}
	d := time.Until(t)
	if d < 0 {
		d = -d
		return "expired " + formatRelDuration(d) + " ago"
	}
	return "in " + formatRelDuration(d)
}

// formatRelDuration formats a time.Duration in a compact human-readable form.
func formatRelDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

// rawJSONString extracts the unquoted string value from a JSON raw message
// that may be a string, number, or other scalar.
func rawJSONString(b json.RawMessage) string {
	if len(b) == 0 {
		return ""
	}
	// Try string
	var s string
	if json.Unmarshal(b, &s) == nil {
		return s
	}
	// Fall back to raw bytes (number, etc.)
	return strings.Trim(string(b), `"`)
}

// parseLLDPCapabilities turns the YANG system-capabilities-enabled bits
// value into a readable comma-separated string.
// The value may arrive as a JSON string of space-separated bit names,
// a JSON object, or be absent; all cases are handled gracefully.
func parseLLDPCapabilities(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try plain string first (some implementations encode as "bridge router")
	var s string
	if json.Unmarshal(raw, &s) == nil {
		parts := strings.Fields(s)
		return strings.Join(parts, ", ")
	}
	// Try array of strings
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return strings.Join(arr, ", ")
	}
	// Fallback: return raw minus braces
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "{}" || trimmed == "null" || trimmed == "[]" {
		return ""
	}
	return trimmed
}
