package components

import (
	"fmt"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestTransitGateway_AttachmentAwareRouting(t *testing.T) {
	tests := []struct {
		name                string
		tgwData             *domain.TransitGatewayData
		ingressAttachmentID string
		dest                domain.RoutingTarget
		setupMock           func(*mockAccountContext)
		wantErr             bool
		wantErrContains     string
		wantComponentType   string
	}{
		{
			name: "routes via associated route table",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-target", Type: "vpc", ResourceID: "vpc-target", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.tgwAttachments["tgw-attach-target"] = &domain.TGWAttachmentData{
					ID:               "tgw-attach-target",
					TransitGatewayID: "tgw-123",
					VPCID:            "vpc-target",
					SubnetIDs:        []string{"subnet-1"},
					State:            "available",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr:           false,
			wantComponentType: "*components.TransitGatewayVPCAttachmentInbound",
		},
		{
			name: "routes via propagated route table",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Propagations: []domain.TGWRouteTablePropagation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "enabled"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-target", Type: "vpc", ResourceID: "vpc-target", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.tgwAttachments["tgw-attach-target"] = &domain.TGWAttachmentData{
					ID:               "tgw-attach-target",
					TransitGatewayID: "tgw-123",
					VPCID:            "vpc-target",
					SubnetIDs:        []string{"subnet-1"},
					State:            "available",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr:           false,
			wantComponentType: "*components.TransitGatewayVPCAttachmentInbound",
		},
		{
			name: "ignores route table not associated or propagated to ingress",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-other", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-target", Type: "vpc", ResourceID: "vpc-target", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "no transit gateway route",
		},
		{
			name: "ignores blackhole route state",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "blackhole",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-target", Type: "vpc", ResourceID: "vpc-target", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "no transit gateway route",
		},
		{
			name: "skips unavailable attachment picks available one",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-pending", Type: "vpc", ResourceID: "vpc-pending", OwnerID: "111111111111", State: "pending"},
									{ID: "tgw-attach-available", Type: "vpc", ResourceID: "vpc-available", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.tgwAttachments["tgw-attach-available"] = &domain.TGWAttachmentData{
					ID:               "tgw-attach-available",
					TransitGatewayID: "tgw-123",
					VPCID:            "vpc-available",
					SubnetIDs:        []string{"subnet-1"},
					State:            "available",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr:           false,
			wantComponentType: "*components.TransitGatewayVPCAttachmentInbound",
		},
		{
			name: "blocks when selected attachment state not available",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-target", Type: "vpc", ResourceID: "vpc-target", OwnerID: "111111111111", State: "modifying"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "no transit gateway route",
		},
		{
			name: "routes to peering attachment",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-peering", Type: "peering", ResourceID: "tgw-attach-peering", OwnerID: "222222222222", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.tgwPeerings["tgw-attach-peering"] = &domain.TGWPeeringAttachmentData{
					ID:                   "tgw-attach-peering",
					TransitGatewayID:     "tgw-123",
					PeerTransitGatewayID: "tgw-peer",
					PeerAccountID:        "222222222222",
				}
				ctx.addClient("222222222222", client)
			},
			wantErr:           false,
			wantComponentType: "*components.TGWPeeringAttachment",
		},
		{
			name: "routes to VPN attachment",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "192.168.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-vpn", Type: "vpn", ResourceID: "vpn-12345", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "192.168.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.vpnConnections["vpn-12345"] = &domain.VPNConnectionData{
					ID:          "vpn-12345",
					VGWID:       "vgw-123",
					State:       "available",
					HasUpTunnel: true,
				}
				ctx.addClient("111111111111", client)
			},
			wantErr:           false,
			wantComponentType: "*components.VPNConnection",
		},
		{
			name: "routes to Direct Connect Gateway",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "172.16.0.0/12",
								PrefixLength:    12,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-dxgw", Type: "direct-connect-gateway", ResourceID: "dxgw-12345", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "172.16.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.dxGateways["dxgw-12345"] = &domain.DirectConnectGatewayData{
					ID:      "dxgw-12345",
					OwnerID: "111111111111",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr:           false,
			wantComponentType: "*components.DirectConnectGateway",
		},
		{
			name: "returns error for unsupported attachment type",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Associations: []domain.TGWRouteTableAssociation{
							{AttachmentID: "tgw-attach-ingress", ResourceType: "vpc", State: "associated"},
						},
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-unknown", Type: "unknown-type", ResourceID: "unknown-123", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "tgw-attach-ingress",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "unsupported TGW attachment type",
		},
		{
			name: "uses all route tables when no ingress attachment",
			tgwData: &domain.TransitGatewayData{
				ID:      "tgw-123",
				OwnerID: "111111111111",
				RouteTables: []domain.TGWRouteTableData{
					{
						ID: "tgw-rtb-1",
						Routes: []domain.TGWRoute{
							{
								DestinationCIDR: "10.0.0.0/16",
								PrefixLength:    16,
								State:           "active",
								Attachments: []domain.TGWRouteAttachment{
									{ID: "tgw-attach-target", Type: "vpc", ResourceID: "vpc-target", OwnerID: "111111111111", State: "available"},
								},
							},
						},
					},
				},
			},
			ingressAttachmentID: "",
			dest:                domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.tgwAttachments["tgw-attach-target"] = &domain.TGWAttachmentData{
					ID:               "tgw-attach-target",
					TransitGatewayID: "tgw-123",
					VPCID:            "vpc-target",
					SubnetIDs:        []string{"subnet-1"},
					State:            "available",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr:           false,
			wantComponentType: "*components.TransitGatewayVPCAttachmentInbound",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountCtx := newMockAccountContext()
			tt.setupMock(accountCtx)
			analyzerCtx := newMockAnalyzerContext(accountCtx)

			tgw := NewTransitGateway(tt.tgwData, "111111111111", tt.ingressAttachmentID)

			components, err := tgw.GetNextHops(tt.dest, analyzerCtx)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.wantErrContains != "" {
					if !stringContains(err.Error(), tt.wantErrContains) {
						t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(components) == 0 {
				t.Errorf("expected at least one component, got none")
				return
			}

			gotType := fmt.Sprintf("%T", components[0])
			if gotType != tt.wantComponentType {
				t.Errorf("component type = %s, want %s", gotType, tt.wantComponentType)
			}
		})
	}
}

func TestTransitGatewayAttachment_StateBlocking(t *testing.T) {
	tests := []struct {
		name            string
		attachmentData  *domain.TGWAttachmentData
		accountID       string
		dest            domain.RoutingTarget
		setupMock       func(*mockAccountContext)
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "allows available state",
			attachmentData: &domain.TGWAttachmentData{
				ID:               "tgw-attach-123",
				TransitGatewayID: "tgw-123",
				TGWAccountID:     "111111111111",
				VPCID:            "vpc-123",
				State:            "available",
			},
			accountID: "111111111111",
			dest:      domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.transitGWs["tgw-123"] = &domain.TransitGatewayData{
					ID:      "tgw-123",
					OwnerID: "111111111111",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr: false,
		},
		{
			name: "blocks pending state",
			attachmentData: &domain.TGWAttachmentData{
				ID:               "tgw-attach-123",
				TransitGatewayID: "tgw-123",
				TGWAccountID:     "111111111111",
				VPCID:            "vpc-123",
				State:            "pending",
			},
			accountID: "111111111111",
			dest:      domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "TGW attachment state is pending",
		},
		{
			name: "blocks modifying state",
			attachmentData: &domain.TGWAttachmentData{
				ID:               "tgw-attach-123",
				TransitGatewayID: "tgw-123",
				TGWAccountID:     "111111111111",
				VPCID:            "vpc-123",
				State:            "modifying",
			},
			accountID: "111111111111",
			dest:      domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "TGW attachment state is modifying",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountCtx := newMockAccountContext()
			tt.setupMock(accountCtx)
			analyzerCtx := newMockAnalyzerContext(accountCtx)

			tga := NewTransitGatewayAttachment(tt.attachmentData, tt.accountID)

			_, err := tga.GetNextHops(tt.dest, analyzerCtx)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.wantErrContains != "" {
					if !stringContains(err.Error(), tt.wantErrContains) {
						t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTransitGatewayVPCAttachmentInbound_StateBlocking(t *testing.T) {
	tests := []struct {
		name            string
		attachmentData  *domain.TGWAttachmentData
		accountID       string
		dest            domain.RoutingTarget
		setupMock       func(*mockAccountContext)
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "allows available state",
			attachmentData: &domain.TGWAttachmentData{
				ID:               "tgw-attach-123",
				TransitGatewayID: "tgw-123",
				VPCID:            "vpc-123",
				SubnetIDs:        []string{"subnet-1"},
				State:            "available",
			},
			accountID: "111111111111",
			dest:      domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				client.subnets["subnet-1"] = &domain.SubnetData{
					ID:           "subnet-1",
					VPCID:        "vpc-123",
					CIDRBlock:    "10.0.1.0/24",
					RouteTableID: "rtb-1",
				}
				client.routeTables["rtb-1"] = &domain.RouteTableData{
					ID:    "rtb-1",
					VPCID: "vpc-123",
				}
				ctx.addClient("111111111111", client)
			},
			wantErr: false,
		},
		{
			name: "blocks pending state",
			attachmentData: &domain.TGWAttachmentData{
				ID:               "tgw-attach-123",
				TransitGatewayID: "tgw-123",
				VPCID:            "vpc-123",
				SubnetIDs:        []string{"subnet-1"},
				State:            "pending",
			},
			accountID: "111111111111",
			dest:      domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"},
			setupMock: func(ctx *mockAccountContext) {
				client := newMockAWSClient()
				ctx.addClient("111111111111", client)
			},
			wantErr:         true,
			wantErrContains: "TGW VPC attachment state is pending",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountCtx := newMockAccountContext()
			tt.setupMock(accountCtx)
			analyzerCtx := newMockAnalyzerContext(accountCtx)

			tga := NewTransitGatewayVPCAttachmentInbound(tt.attachmentData, tt.accountID)

			_, err := tga.GetNextHops(tt.dest, analyzerCtx)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}
				if tt.wantErrContains != "" {
					if !stringContains(err.Error(), tt.wantErrContains) {
						t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTGWPeeringAttachment_ThreadsAttachmentID(t *testing.T) {
	accountCtx := newMockAccountContext()
	client := newMockAWSClient()
	client.transitGWs["tgw-peer"] = &domain.TransitGatewayData{
		ID:      "tgw-peer",
		OwnerID: "222222222222",
	}
	accountCtx.addClient("222222222222", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tpa := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{
		ID:                   "tgw-attach-peering",
		TransitGatewayID:     "tgw-local",
		PeerTransitGatewayID: "tgw-peer",
		PeerAccountID:        "222222222222",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.5", Port: 443, Protocol: "tcp"}
	components, err := tpa.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}

	tgw, ok := components[0].(*TransitGateway)
	if !ok {
		t.Fatalf("expected TransitGateway, got %T", components[0])
	}

	if tgw.ingressAttachmentID != "tgw-attach-peering" {
		t.Errorf("expected ingressAttachmentID tgw-attach-peering, got %s", tgw.ingressAttachmentID)
	}
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
