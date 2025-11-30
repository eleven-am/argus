package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/sync/errgroup"

	"github.com/eleven-am/argus/internal/domain"
)

func (c *Client) GetTransitGateway(ctx context.Context, tgwID string) (*domain.TransitGatewayData, error) {
	key := c.cacheKey("tgw", tgwID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.TransitGatewayData), nil
	}
	out, err := c.ec2Client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
		TransitGatewayIds: []string{tgwID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe transit gateway %s: %w", tgwID, err)
	}
	if len(out.TransitGateways) == 0 {
		return nil, fmt.Errorf("transit gateway %s not found", tgwID)
	}

	rts, err := c.fetchTGWRouteTables(ctx, tgwID)
	if err != nil {
		return nil, err
	}

	data := toTransitGatewayData(&out.TransitGateways[0], rts)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) fetchTGWRouteTables(ctx context.Context, tgwID string) ([]domain.TGWRouteTableData, error) {
	input := &ec2.DescribeTransitGatewayRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("transit-gateway-id"), Values: []string{tgwID}},
		},
	}
	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(c.ec2Client, input)
	routeTables, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*ec2.DescribeTransitGatewayRouteTablesOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *ec2.DescribeTransitGatewayRouteTablesOutput) []ec2types.TransitGatewayRouteTable {
			return out.TransitGatewayRouteTables
		},
	)
	if err != nil {
		return nil, fmt.Errorf("describe tgw route tables for %s: %w", tgwID, err)
	}

	results := make([]domain.TGWRouteTableData, len(routeTables))
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, rt := range routeTables {
		i, rt := i, rt
		g.Go(func() error {
			rtID := derefString(rt.TransitGatewayRouteTableId)

			var routes []domain.TGWRoute
			var associations []domain.TGWRouteTableAssociation
			var propagations []domain.TGWRouteTablePropagation

			innerG, innerCtx := errgroup.WithContext(gCtx)

			innerG.Go(func() error {
				var err error
				routes, err = c.searchTGWRoutes(innerCtx, rtID)
				return err
			})
			innerG.Go(func() error {
				var err error
				associations, err = c.fetchTGWRouteTableAssociations(innerCtx, rtID)
				return err
			})
			innerG.Go(func() error {
				var err error
				propagations, err = c.fetchTGWRouteTablePropagations(innerCtx, rtID)
				return err
			})

			if err := innerG.Wait(); err != nil {
				return err
			}

			results[i] = domain.TGWRouteTableData{
				ID:           rtID,
				Routes:       routes,
				Associations: associations,
				Propagations: propagations,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Client) fetchTGWRouteTableAssociations(ctx context.Context, rtID string) ([]domain.TGWRouteTableAssociation, error) {
	out, err := c.ec2Client.GetTransitGatewayRouteTableAssociations(ctx, &ec2.GetTransitGatewayRouteTableAssociationsInput{
		TransitGatewayRouteTableId: aws.String(rtID),
	})
	if err != nil {
		return nil, fmt.Errorf("get tgw route table associations for %s: %w", rtID, err)
	}

	var associations []domain.TGWRouteTableAssociation
	for _, a := range out.Associations {
		associations = append(associations, domain.TGWRouteTableAssociation{
			AttachmentID: derefString(a.TransitGatewayAttachmentId),
			ResourceType: string(a.ResourceType),
			State:        string(a.State),
		})
	}
	return associations, nil
}

func (c *Client) fetchTGWRouteTablePropagations(ctx context.Context, rtID string) ([]domain.TGWRouteTablePropagation, error) {
	out, err := c.ec2Client.GetTransitGatewayRouteTablePropagations(ctx, &ec2.GetTransitGatewayRouteTablePropagationsInput{
		TransitGatewayRouteTableId: aws.String(rtID),
	})
	if err != nil {
		return nil, fmt.Errorf("get tgw route table propagations for %s: %w", rtID, err)
	}

	var propagations []domain.TGWRouteTablePropagation
	for _, p := range out.TransitGatewayRouteTablePropagations {
		propagations = append(propagations, domain.TGWRouteTablePropagation{
			AttachmentID: derefString(p.TransitGatewayAttachmentId),
			ResourceType: string(p.ResourceType),
			State:        string(p.State),
		})
	}
	return propagations, nil
}

func (c *Client) searchTGWRoutes(ctx context.Context, rtID string) ([]domain.TGWRoute, error) {
	searchFilters := []ec2types.Filter{
		{Name: aws.String("type"), Values: []string{"static", "propagated"}},
	}

	out, err := c.ec2Client.SearchTransitGatewayRoutes(ctx, &ec2.SearchTransitGatewayRoutesInput{
		TransitGatewayRouteTableId: aws.String(rtID),
		Filters:                    searchFilters,
	})
	if err != nil {
		return nil, fmt.Errorf("search tgw routes for %s: %w", rtID, err)
	}

	var routes []domain.TGWRoute
	attachmentIDs := make(map[string]struct{})
	for _, r := range out.Routes {
		for _, att := range r.TransitGatewayAttachments {
			if att.TransitGatewayAttachmentId != nil {
				attachmentIDs[*att.TransitGatewayAttachmentId] = struct{}{}
			}
		}
	}

	attDetailsMap := make(map[string]ec2types.TransitGatewayAttachment)
	if len(attachmentIDs) > 0 {
		var ids []string
		for id := range attachmentIDs {
			ids = append(ids, id)
		}
		details, err := c.ec2Client.DescribeTransitGatewayAttachments(ctx, &ec2.DescribeTransitGatewayAttachmentsInput{
			TransitGatewayAttachmentIds: ids,
		})
		if err == nil {
			for _, att := range details.TransitGatewayAttachments {
				if att.TransitGatewayAttachmentId != nil {
					attDetailsMap[*att.TransitGatewayAttachmentId] = att
				}
			}
		}
	}

	for _, r := range out.Routes {
		route := domain.TGWRoute{
			DestinationCIDR:         derefString(r.DestinationCidrBlock),
			DestinationPrefixListID: derefString(r.PrefixListId),
			PrefixLength:            prefixLength(derefString(r.DestinationCidrBlock)),
			State:                   string(r.State),
		}

		for _, att := range r.TransitGatewayAttachments {
			attState := ""
			ownerID := ""
			if att.TransitGatewayAttachmentId != nil {
				if det, ok := attDetailsMap[*att.TransitGatewayAttachmentId]; ok {
					attState = string(det.State)
					ownerID = derefString(det.ResourceOwnerId)
				}
			}

			route.Attachments = append(route.Attachments, domain.TGWRouteAttachment{
				ID:         derefString(att.TransitGatewayAttachmentId),
				Type:       string(att.ResourceType),
				ResourceID: derefString(att.ResourceId),
				OwnerID:    ownerID,
				State:      attState,
			})
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func (c *Client) GetTransitGatewayAttachment(ctx context.Context, vpcID, tgwID string) (*domain.TGWAttachmentData, error) {
	key := c.cacheKey("tgw-attach-vpc", vpcID+":"+tgwID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.TGWAttachmentData), nil
	}
	out, err := c.ec2Client.DescribeTransitGatewayVpcAttachments(ctx, &ec2.DescribeTransitGatewayVpcAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("transit-gateway-id"), Values: []string{tgwID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe tgw attachment for vpc %s tgw %s: %w", vpcID, tgwID, err)
	}
	if len(out.TransitGatewayVpcAttachments) == 0 {
		return nil, fmt.Errorf("tgw attachment not found for vpc %s tgw %s", vpcID, tgwID)
	}

	att := &out.TransitGatewayVpcAttachments[0]
	attachmentID := derefString(att.TransitGatewayAttachmentId)

	tgwOwnerID := ""
	tgwOut, err := c.ec2Client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
		TransitGatewayIds: []string{tgwID},
	})
	if err == nil && len(tgwOut.TransitGateways) > 0 {
		tgwOwnerID = derefString(tgwOut.TransitGateways[0].OwnerId)
	}

	state := string(att.State)

	propagatedRTIDs, err := c.getPropagatedRouteTableIDs(ctx, tgwID, attachmentID)
	if err != nil {
		propagatedRTIDs = nil
	}

	data := toTGWAttachmentData(att, tgwOwnerID, state, propagatedRTIDs)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetTransitGatewayAttachmentByID(ctx context.Context, attachmentID string) (*domain.TGWAttachmentData, error) {
	key := c.cacheKey("tgw-attach", attachmentID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.TGWAttachmentData), nil
	}
	out, err := c.ec2Client.DescribeTransitGatewayVpcAttachments(ctx, &ec2.DescribeTransitGatewayVpcAttachmentsInput{
		TransitGatewayAttachmentIds: []string{attachmentID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe tgw attachment %s: %w", attachmentID, err)
	}
	if len(out.TransitGatewayVpcAttachments) == 0 {
		return nil, fmt.Errorf("tgw attachment %s not found", attachmentID)
	}

	att := &out.TransitGatewayVpcAttachments[0]
	tgwID := derefString(att.TransitGatewayId)

	tgwOwnerID := ""
	if tgwID != "" {
		tgwOut, err := c.ec2Client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
			TransitGatewayIds: []string{tgwID},
		})
		if err == nil && len(tgwOut.TransitGateways) > 0 {
			tgwOwnerID = derefString(tgwOut.TransitGateways[0].OwnerId)
		}
	}

	state := string(att.State)

	propagatedRTIDs, err := c.getPropagatedRouteTableIDs(ctx, tgwID, attachmentID)
	if err != nil {
		propagatedRTIDs = nil
	}

	data := toTGWAttachmentData(att, tgwOwnerID, state, propagatedRTIDs)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetRouteTablesForAttachment(ctx context.Context, tgwID, attachmentID string) (associated []string, propagated []string, err error) {
	input := &ec2.DescribeTransitGatewayRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("transit-gateway-id"), Values: []string{tgwID}},
		},
	}
	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(c.ec2Client, input)
	routeTables, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*ec2.DescribeTransitGatewayRouteTablesOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *ec2.DescribeTransitGatewayRouteTablesOutput) []ec2types.TransitGatewayRouteTable {
			return out.TransitGatewayRouteTables
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("describe tgw route tables for %s: %w", tgwID, err)
	}

	type rtResult struct {
		rtID       string
		associated bool
		propagated bool
	}

	results := make([]rtResult, len(routeTables))
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, rt := range routeTables {
		i, rt := i, rt
		g.Go(func() error {
			rtID := derefString(rt.TransitGatewayRouteTableId)
			results[i].rtID = rtID

			innerG, innerCtx := errgroup.WithContext(gCtx)

			innerG.Go(func() error {
				assocOut, err := c.ec2Client.GetTransitGatewayRouteTableAssociations(innerCtx, &ec2.GetTransitGatewayRouteTableAssociationsInput{
					TransitGatewayRouteTableId: aws.String(rtID),
				})
				if err == nil {
					for _, a := range assocOut.Associations {
						if derefString(a.TransitGatewayAttachmentId) == attachmentID && a.State == ec2types.TransitGatewayAssociationStateAssociated {
							results[i].associated = true
							break
						}
					}
				}
				return nil
			})

			innerG.Go(func() error {
				propOut, err := c.ec2Client.GetTransitGatewayRouteTablePropagations(innerCtx, &ec2.GetTransitGatewayRouteTablePropagationsInput{
					TransitGatewayRouteTableId: aws.String(rtID),
				})
				if err == nil {
					for _, p := range propOut.TransitGatewayRouteTablePropagations {
						if derefString(p.TransitGatewayAttachmentId) == attachmentID && p.State == ec2types.TransitGatewayPropagationStateEnabled {
							results[i].propagated = true
							break
						}
					}
				}
				return nil
			})

			innerG.Wait()
			return nil
		})
	}

	g.Wait()

	for _, r := range results {
		if r.associated {
			associated = append(associated, r.rtID)
		}
		if r.propagated {
			propagated = append(propagated, r.rtID)
		}
	}

	return associated, propagated, nil
}

func (c *Client) getPropagatedRouteTableIDs(ctx context.Context, tgwID, attachmentID string) ([]string, error) {
	_, propagated, err := c.GetRouteTablesForAttachment(ctx, tgwID, attachmentID)
	return propagated, err
}

func (c *Client) GetTGWPeeringAttachment(ctx context.Context, attachmentID string) (*domain.TGWPeeringAttachmentData, error) {
	out, err := c.ec2Client.DescribeTransitGatewayPeeringAttachments(ctx, &ec2.DescribeTransitGatewayPeeringAttachmentsInput{
		TransitGatewayAttachmentIds: []string{attachmentID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe tgw peering attachment %s: %w", attachmentID, err)
	}
	if len(out.TransitGatewayPeeringAttachments) == 0 {
		return nil, fmt.Errorf("tgw peering attachment %s not found", attachmentID)
	}
	peering := &out.TransitGatewayPeeringAttachments[0]
	return &domain.TGWPeeringAttachmentData{
		ID:                   derefString(peering.TransitGatewayAttachmentId),
		TransitGatewayID:     derefString(peering.RequesterTgwInfo.TransitGatewayId),
		PeerTransitGatewayID: derefString(peering.AccepterTgwInfo.TransitGatewayId),
		PeerAccountID:        derefString(peering.AccepterTgwInfo.OwnerId),
	}, nil
}
