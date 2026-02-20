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

	"github.com/kernelkit/infix-webui/internal/restconf"
)

type RouteEntry struct {
	DestPrefix   string
	NextHopIface string
	NextHopAddr  string
	Protocol     string
	Preference   int
	Active       bool
}

type OSPFNeighbor struct {
	RouterID  string
	State     string
	Role      string
	Interface string
	Uptime    string
}

type OSPFIface struct {
	Name  string
	State string
	Cost  int
	DR    string
	BDR   string
}

type routingData struct {
	CsrfToken     string
	PageTitle     string
	ActivePage    string
	Capabilities  *Capabilities
	Routes        []RouteEntry
	OSPFNeighbors []OSPFNeighbor
	OSPFIfaces    []OSPFIface
	HasOSPF       bool
	Error         string
}

type RoutingHandler struct {
	Template *template.Template
	RC       *restconf.Client
}

type ribWrapper struct {
	Rib  []ribJSON `json:"ietf-routing:rib"`
	Ribs *struct {
		Rib []ribJSON `json:"rib"`
	} `json:"ietf-routing:ribs"`
}

type ribJSON struct {
	Name   string        `json:"name"`
	Routes ribRoutesJSON `json:"routes"`
}

type ribRoutesJSON struct {
	Route []ribRouteJSON `json:"route"`
}

type ribRouteJSON struct {
	DestinationPrefix string           `json:"destination-prefix"`
	NextHop           ribNextHopJSON   `json:"next-hop"`
	SourceProtocol    string           `json:"source-protocol"`
	Active            *json.RawMessage `json:"active"`
	RoutePreference   int              `json:"route-preference"`
}

type ribNextHopJSON struct {
	OutgoingInterface string `json:"outgoing-interface"`
	NextHopAddress    string `json:"next-hop-address"`
}

type ospfCPPWrapper struct {
	Routing struct {
		CPP struct {
			Protocol []ospfProtocolJSON `json:"control-plane-protocol"`
		} `json:"control-plane-protocols"`
	} `json:"ietf-routing:routing"`
}

type ospfProtocolJSON struct {
	Type string   `json:"type"`
	Name string   `json:"name"`
	OSPF ospfJSON `json:"ospf:ospf"`
}

type ospfJSON struct {
	Areas struct {
		Area []ospfAreaJSON `json:"area"`
	} `json:"areas"`
}

type ospfAreaJSON struct {
	AreaID     string `json:"area-id"`
	Interfaces struct {
		Interface []ospfIfaceJSON `json:"interface"`
	} `json:"interfaces"`
}

type ospfIfaceJSON struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Cost        int    `json:"cost"`
	DRRouterID  string `json:"dr-router-id"`
	BDRRouterID string `json:"bdr-router-id"`
	Neighbors   struct {
		Neighbor []ospfNeighborJSON `json:"neighbor"`
	} `json:"neighbors"`
}

type ospfNeighborJSON struct {
	NeighborRouterID string `json:"neighbor-router-id"`
	State            string `json:"state"`
	Role             string `json:"infix-routing:role"`
	InterfaceName    string `json:"infix-routing:interface-name"`
	Uptime           uint32 `json:"infix-routing:uptime"`
}

func (h *RoutingHandler) Overview(w http.ResponseWriter, r *http.Request) {
	data := routingData{
		CsrfToken:    csrfToken(r.Context()),
		PageTitle:    "Routing",
		ActivePage:   "routing",
		Capabilities: DetectCapabilities(r.Context(), h.RC),
	}

	ctx := context.WithoutCancel(r.Context())

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		var rib ribWrapper
		if err := h.RC.Get(ctx, "/data/ietf-routing:routing/ribs/rib", &rib); err != nil {
			log.Printf("restconf rib: %v", err)
			return
		}
		ribs := rib.Rib
		if len(ribs) == 0 && rib.Ribs != nil {
			ribs = rib.Ribs.Rib
		}
		for _, rb := range ribs {
			for _, route := range rb.Routes.Route {
				data.Routes = append(data.Routes, RouteEntry{
					DestPrefix:   route.DestinationPrefix,
					NextHopIface: route.NextHop.OutgoingInterface,
					NextHopAddr:  route.NextHop.NextHopAddress,
					Protocol:     shortProto(route.SourceProtocol),
					Preference:   route.RoutePreference,
					Active:       route.Active != nil,
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		var cpp ospfCPPWrapper
		if err := h.RC.Get(ctx,
			"/data/ietf-routing:routing/control-plane-protocols/control-plane-protocol=infix-routing:ospfv2,ospf",
			&cpp); err != nil {
			log.Printf("restconf ospf (ignored): %v", err)
			return
		}
		data.HasOSPF = true
		for _, proto := range cpp.Routing.CPP.Protocol {
			for _, area := range proto.OSPF.Areas.Area {
				for _, iface := range area.Interfaces.Interface {
					data.OSPFIfaces = append(data.OSPFIfaces, OSPFIface{
						Name:  iface.Name,
						State: iface.State,
						Cost:  iface.Cost,
						DR:    iface.DRRouterID,
						BDR:   iface.BDRRouterID,
					})
					for _, nbr := range iface.Neighbors.Neighbor {
						data.OSPFNeighbors = append(data.OSPFNeighbors, OSPFNeighbor{
							RouterID:  nbr.NeighborRouterID,
							State:     nbr.State,
							Role:      nbr.Role,
							Interface: iface.Name,
							Uptime:    formatUptime(nbr.Uptime),
						})
					}
				}
			}
		}
	}()

	wg.Wait()

	tmplName := "routing.html"
	if r.Header.Get("HX-Request") == "true" {
		tmplName = "content"
	}
	if err := h.Template.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func shortProto(proto string) string {
	if i := strings.LastIndex(proto, ":"); i >= 0 {
		return proto[i+1:]
	}
	return proto
}

func formatUptime(sec uint32) string {
	if sec == 0 {
		return ""
	}
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	secs := sec % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm %ds", mins, secs)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}
