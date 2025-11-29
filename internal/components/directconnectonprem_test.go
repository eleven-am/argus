package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestDirectConnectOnPrem_GetID(t *testing.T) {
	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP: "192.168.1.100",
		DXGWID:   "dxgw-123",
	}, "123456789012")

	expected := "123456789012:dxonprem:192.168.1.100"
	if onprem.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, onprem.GetID())
	}
}

func TestDirectConnectOnPrem_GetID_WithCIDR(t *testing.T) {
	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		OnPremCIDR: "192.168.0.0/16",
		DXGWID:     "dxgw-123",
	}, "123456789012")

	expected := "123456789012:dxonprem:192.168.0.0/16"
	if onprem.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, onprem.GetID())
	}
}

func TestDirectConnectOnPrem_GetAccountID(t *testing.T) {
	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP: "192.168.1.100",
	}, "123456789012")

	if onprem.GetAccountID() != "123456789012" {
		t.Errorf("expected account ID 123456789012, got %s", onprem.GetAccountID())
	}
}

func TestDirectConnectOnPrem_GetRoutingTarget(t *testing.T) {
	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP: "192.168.1.100",
		DXGWID:   "dxgw-123",
	}, "123456789012")

	target := onprem.GetRoutingTarget()

	if target.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", target.IP)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", target.Protocol)
	}
	if !target.SourceIsPrivate {
		t.Error("expected SourceIsPrivate to be true")
	}
}

func TestDirectConnectOnPrem_GetNextHops_InvalidState(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP:        "192.168.1.100",
		DXGWID:          "dxgw-123",
		AttachmentState: "detached",
	}, "123456789012")

	_, err := onprem.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for detached attachment state")
	}
	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockErr.Reason == "" {
		t.Error("expected non-empty reason in BlockingError")
	}
}

func TestDirectConnectOnPrem_GetNextHops_PrefixNotAllowed(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP:        "192.168.1.100",
		OnPremCIDR:      "192.168.0.0/16",
		DXGWID:          "dxgw-123",
		AttachmentState: "attached",
		AllowedPrefixes: []string{"10.0.0.0/8"},
	}, "123456789012")

	_, err := onprem.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for disallowed prefix")
	}
	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockErr.Reason == "" {
		t.Error("expected non-empty reason in BlockingError")
	}
}

func TestDirectConnectOnPrem_GetNextHops_NoDXGWID(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP:        "192.168.1.100",
		AttachmentState: "attached",
	}, "123456789012")

	_, err := onprem.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for missing DXGW ID")
	}
	var blockingError *domain.BlockingError
	if !errors.As(err, &blockingError) {
		t.Fatalf("expected BlockingError, got %T", err)
	}
}

func TestDirectConnectOnPrem_GetNextHops_Success(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.dxGateways["dxgw-123"] = &domain.DirectConnectGatewayData{
		ID:    "dxgw-123",
		State: "available",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	onprem := NewDirectConnectOnPrem(&domain.DirectConnectOnPremData{
		SourceIP:        "192.168.1.100",
		OnPremCIDR:      "192.168.0.0/16",
		DXGWID:          "dxgw-123",
		AttachmentState: "attached",
		AllowedPrefixes: []string{"192.168.0.0/16"},
	}, "123456789012")

	hops, err := onprem.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (DXGW), got %d", len(hops))
	}
}
