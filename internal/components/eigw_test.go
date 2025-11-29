package components

import (
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestEgressOnlyInternetGateway_GetNextHops(t *testing.T) {
	eigw := NewEgressOnlyInternetGateway(&domain.EgressOnlyInternetGatewayData{
		ID:    "eigw-12345",
		VPCID: "vpc-12345",
	}, "123456789012")

	tests := []struct {
		name        string
		dest        domain.RoutingTarget
		wantErr     bool
		errContains string
	}{
		{
			name: "allows outbound IPv6 to external address",
			dest: domain.RoutingTarget{
				IP:        "2600:1f18:1234:5678::1",
				Port:      443,
				Direction: "outbound",
			},
			wantErr: false,
		},
		{
			name: "blocks inbound traffic",
			dest: domain.RoutingTarget{
				IP:        "2600:1f18:1234:5678::1",
				Port:      443,
				Direction: "inbound",
			},
			wantErr:     true,
			errContains: "only allows outbound traffic",
		},
		{
			name: "blocks IPv4 traffic",
			dest: domain.RoutingTarget{
				IP:        "8.8.8.8",
				Port:      443,
				Direction: "outbound",
			},
			wantErr:     true,
			errContains: "only supports IPv6 traffic",
		},
		{
			name: "blocks private IPv6 addresses",
			dest: domain.RoutingTarget{
				IP:        "fd00::1",
				Port:      443,
				Direction: "outbound",
			},
			wantErr:     true,
			errContains: "can only route to external",
		},
		{
			name: "blocks link-local IPv6 addresses",
			dest: domain.RoutingTarget{
				IP:        "fe80::1",
				Port:      443,
				Direction: "outbound",
			},
			wantErr:     true,
			errContains: "can only route to external",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hops, err := eigw.GetNextHops(tt.dest, nil)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
					return
				}
				blockErr, ok := err.(*domain.BlockingError)
				if !ok {
					t.Errorf("expected BlockingError, got %T", err)
					return
				}
				if tt.errContains != "" && !containsString(blockErr.Reason, tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, blockErr.Reason)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(hops) != 1 {
					t.Errorf("expected 1 hop, got %d", len(hops))
				}
			}
		})
	}
}

func TestEgressOnlyInternetGateway_ComponentMethods(t *testing.T) {
	eigw := NewEgressOnlyInternetGateway(&domain.EgressOnlyInternetGatewayData{
		ID:    "eigw-12345",
		VPCID: "vpc-12345",
	}, "123456789012")

	if got := eigw.GetID(); got != "123456789012:eigw-12345" {
		t.Errorf("GetID() = %q, want %q", got, "123456789012:eigw-12345")
	}

	if got := eigw.GetAccountID(); got != "123456789012" {
		t.Errorf("GetAccountID() = %q, want %q", got, "123456789012")
	}

	if got := eigw.GetComponentType(); got != "EgressOnlyInternetGateway" {
		t.Errorf("GetComponentType() = %q, want %q", got, "EgressOnlyInternetGateway")
	}

	if got := eigw.GetVPCID(); got != "vpc-12345" {
		t.Errorf("GetVPCID() = %q, want %q", got, "vpc-12345")
	}

	if !eigw.IsTerminal() {
		t.Error("IsTerminal() should return true")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
