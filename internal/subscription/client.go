package subscription

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/erp-suite/erp-api-gateway/proto"
)

// Client represents a subscription service gRPC client
type Client struct {
	conn   *grpc.ClientConn
	client proto.SubscriptionServiceClient
}

// NewClient creates a new subscription service client
func NewClient(subscriptionServiceURL string) (*Client, error) {
	conn, err := grpc.Dial(subscriptionServiceURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to subscription service: %w", err)
	}

	client := proto.NewSubscriptionServiceClient(conn)

	return &Client{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// addAuthToken adds authentication token to the context
func (c *Client) addAuthToken(ctx context.Context, token string) context.Context {
	if token != "" {
		md := metadata.New(map[string]string{
			"authorization": "Bearer " + token,
		})
		return metadata.NewOutgoingContext(ctx, md)
	}
	return ctx
}

// HealthCheck checks the health of the subscription service
func (c *Client) HealthCheck(ctx context.Context) (*proto.HealthCheckResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.client.HealthCheck(ctx, &proto.HealthCheckRequest{})
}

// ListPlans retrieves all subscription plans
func (c *Client) ListPlans(ctx context.Context, includeInactive bool) (*proto.ListPlansResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.ListPlans(ctx, &proto.ListPlansRequest{
		IncludeInactive: includeInactive,
	})
}

// GetPlan retrieves a specific plan by ID
func (c *Client) GetPlan(ctx context.Context, planID string) (*proto.GetPlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetPlan(ctx, &proto.GetPlanRequest{
		PlanId: planID,
	})
}

// CreatePlan creates a new subscription plan
func (c *Client) CreatePlan(ctx context.Context, req *proto.CreatePlanRequest) (*proto.CreatePlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.CreatePlan(ctx, req)
}

// UpdatePlan updates an existing subscription plan
func (c *Client) UpdatePlan(ctx context.Context, req *proto.UpdatePlanRequest) (*proto.UpdatePlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.UpdatePlan(ctx, req)
}

// DeletePlan deletes a subscription plan
func (c *Client) DeletePlan(ctx context.Context, planID string) (*proto.DeletePlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.DeletePlan(ctx, &proto.DeletePlanRequest{
		PlanId: planID,
	})
}

// GetSubscription retrieves a subscription for an organization
func (c *Client) GetSubscription(ctx context.Context, organizationID string) (*proto.GetSubscriptionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetSubscription(ctx, &proto.GetSubscriptionRequest{
		OrganizationId: organizationID,
	})
}

// CreateSubscription creates a new subscription
func (c *Client) CreateSubscription(ctx context.Context, req *proto.CreateSubscriptionRequest) (*proto.CreateSubscriptionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	return c.client.CreateSubscription(ctx, req)
}

// UpdateSubscription updates an existing subscription
func (c *Client) UpdateSubscription(ctx context.Context, req *proto.UpdateSubscriptionRequest) (*proto.UpdateSubscriptionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.UpdateSubscription(ctx, req)
}

// CancelSubscription cancels a subscription
func (c *Client) CancelSubscription(ctx context.Context, subscriptionID string, cancelAtPeriodEnd bool) (*proto.CancelSubscriptionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.CancelSubscription(ctx, &proto.CancelSubscriptionRequest{
		SubscriptionId:    subscriptionID,
		CancelAtPeriodEnd: cancelAtPeriodEnd,
	})
}

// ReactivateSubscription reactivates a canceled subscription
func (c *Client) ReactivateSubscription(ctx context.Context, subscriptionID string) (*proto.ReactivateSubscriptionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.ReactivateSubscription(ctx, &proto.ReactivateSubscriptionRequest{
		SubscriptionId: subscriptionID,
	})
}

// ChangePlan changes the plan of a subscription
func (c *Client) ChangePlan(ctx context.Context, req *proto.ChangePlanRequest) (*proto.ChangePlanResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	return c.client.ChangePlan(ctx, req)
}

// ListInvoices retrieves invoices for an organization
func (c *Client) ListInvoices(ctx context.Context, organizationID string, limit, offset int32, status string) (*proto.ListInvoicesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.ListInvoices(ctx, &proto.ListInvoicesRequest{
		OrganizationId: organizationID,
		Limit:          limit,
		Offset:         offset,
		Status:         status,
	})
}

// GetInvoice retrieves a specific invoice by ID
func (c *Client) GetInvoice(ctx context.Context, invoiceID string) (*proto.GetInvoiceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetInvoice(ctx, &proto.GetInvoiceRequest{
		InvoiceId: invoiceID,
	})
}

// CreateInvoice creates a new invoice
func (c *Client) CreateInvoice(ctx context.Context, req *proto.CreateInvoiceRequest) (*proto.CreateInvoiceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.CreateInvoice(ctx, req)
}

// PayInvoice pays an invoice
func (c *Client) PayInvoice(ctx context.Context, req *proto.PayInvoiceRequest) (*proto.PayInvoiceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	return c.client.PayInvoice(ctx, req)
}

// ListPaymentMethods retrieves payment methods for an organization
func (c *Client) ListPaymentMethods(ctx context.Context, organizationID string) (*proto.ListPaymentMethodsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.ListPaymentMethods(ctx, &proto.ListPaymentMethodsRequest{
		OrganizationId: organizationID,
	})
}

// GetPaymentMethod retrieves a specific payment method by ID
func (c *Client) GetPaymentMethod(ctx context.Context, paymentMethodID string) (*proto.GetPaymentMethodResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetPaymentMethod(ctx, &proto.GetPaymentMethodRequest{
		PaymentMethodId: paymentMethodID,
	})
}

// CreatePaymentMethod creates a new payment method
func (c *Client) CreatePaymentMethod(ctx context.Context, req *proto.CreatePaymentMethodRequest) (*proto.CreatePaymentMethodResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.CreatePaymentMethod(ctx, req)
}

// UpdatePaymentMethod updates an existing payment method
func (c *Client) UpdatePaymentMethod(ctx context.Context, req *proto.UpdatePaymentMethodRequest) (*proto.UpdatePaymentMethodResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.UpdatePaymentMethod(ctx, req)
}

// DeletePaymentMethod deletes a payment method
func (c *Client) DeletePaymentMethod(ctx context.Context, paymentMethodID string) (*proto.DeletePaymentMethodResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.DeletePaymentMethod(ctx, &proto.DeletePaymentMethodRequest{
		PaymentMethodId: paymentMethodID,
	})
}

// SetDefaultPaymentMethod sets a payment method as default
func (c *Client) SetDefaultPaymentMethod(ctx context.Context, paymentMethodID string) (*proto.SetDefaultPaymentMethodResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.SetDefaultPaymentMethod(ctx, &proto.SetDefaultPaymentMethodRequest{
		PaymentMethodId: paymentMethodID,
	})
}

// GetUsage retrieves usage for an organization
func (c *Client) GetUsage(ctx context.Context, organizationID, metric, period string) (*proto.GetUsageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetUsage(ctx, &proto.GetUsageRequest{
		OrganizationId: organizationID,
		Metric:         metric,
		Period:         period,
	})
}

// TrackUsage tracks usage for an organization
func (c *Client) TrackUsage(ctx context.Context, req *proto.TrackUsageRequest) (*proto.TrackUsageResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.TrackUsage(ctx, req)
}

// GetUsageHistory retrieves usage history for an organization
func (c *Client) GetUsageHistory(ctx context.Context, organizationID, metric, period string, limit, offset int32) (*proto.GetUsageHistoryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetUsageHistory(ctx, &proto.GetUsageHistoryRequest{
		OrganizationId: organizationID,
		Metric:         metric,
		Period:         period,
		Limit:          limit,
		Offset:         offset,
	})
}

// GetBillingInfo retrieves billing info for an organization
func (c *Client) GetBillingInfo(ctx context.Context, organizationID string) (*proto.GetBillingInfoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.GetBillingInfo(ctx, &proto.GetBillingInfoRequest{
		OrganizationId: organizationID,
	})
}

// UpdateBillingInfo updates billing info for an organization
func (c *Client) UpdateBillingInfo(ctx context.Context, req *proto.UpdateBillingInfoRequest) (*proto.UpdateBillingInfoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return c.client.UpdateBillingInfo(ctx, req)
}
