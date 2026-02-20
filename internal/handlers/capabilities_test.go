package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/kernelkit/infix-webui/internal/testutil"
)

func TestDetectCapabilities_AllUnavailable(t *testing.T) {
	mock := testutil.NewMockFetcher()
	for _, path := range []string{
		"ietf-hardware:hardware",
		"infix-containers:containers",
		"ietf-routing:routing/control-plane-protocols",
		"ietf-interfaces:interfaces",
		"infix-dhcp-server:dhcp-server",
		"ietf-ntp:ntp",
		"ieee802-dot1ab-lldp:lldp",
	} {
		mock.SetError(path, errors.New("not found"))
	}
	caps := DetectCapabilities(context.Background(), mock)
	if caps.WiFi || caps.Containers || caps.OSPF || caps.WireGuard || caps.DHCPServer || caps.NTP || caps.LLDP {
		t.Errorf("expected all caps false, got %+v", caps)
	}
}

func TestDetectCapabilities_ContainersAvailable(t *testing.T) {
	mock := testutil.NewMockFetcher()
	mock.SetResponse("infix-containers:containers", map[string]interface{}{})
	for _, path := range []string{
		"ietf-hardware:hardware",
		"ietf-routing:routing/control-plane-protocols",
		"ietf-interfaces:interfaces",
		"infix-dhcp-server:dhcp-server",
		"ietf-ntp:ntp",
		"ieee802-dot1ab-lldp:lldp",
	} {
		mock.SetError(path, errors.New("not found"))
	}
	caps := DetectCapabilities(context.Background(), mock)
	if !caps.Containers {
		t.Errorf("expected Containers=true, got %+v", caps)
	}
	if caps.WiFi || caps.OSPF || caps.WireGuard || caps.DHCPServer || caps.NTP || caps.LLDP {
		t.Errorf("unexpected caps set: %+v", caps)
	}
}
