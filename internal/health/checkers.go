package health

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
)

// RedisHealthChecker checks Redis connectivity
type RedisHealthChecker struct {
	client *services.RedisClient
}

func NewRedisHealthChecker(client *services.RedisClient) *RedisHealthChecker {
	return &RedisHealthChecker{client: client}
}

func (r *RedisHealthChecker) Name() string {
	return "redis"
}

func (r *RedisHealthChecker) Check(ctx context.Context) error {
	if r.client == nil {
		return fmt.Errorf("redis client not initialized")
	}
	return r.client.Ping(ctx)
}

// GRPCHealthChecker checks gRPC service connectivity
type GRPCHealthChecker struct {
	client      *grpc_client.GRPCClient
	serviceName string
}

func NewGRPCHealthChecker(client *grpc_client.GRPCClient, serviceName string) *GRPCHealthChecker {
	return &GRPCHealthChecker{
		client:      client,
		serviceName: serviceName,
	}
}

func (g *GRPCHealthChecker) Name() string {
	return fmt.Sprintf("grpc_%s", g.serviceName)
}

func (g *GRPCHealthChecker) Check(ctx context.Context) error {
	if g.client == nil {
		return fmt.Errorf("grpc client not initialized")
	}
	
	switch g.serviceName {
	case "auth":
		authClient, err := g.client.AuthService(ctx)
		if err != nil {
			return fmt.Errorf("failed to get auth client: %w", err)
		}
		if authClient == nil {
			return fmt.Errorf("auth client is nil")
		}
		return nil
	default:
		return fmt.Errorf("unknown service: %s", g.serviceName)
	}
}

// KafkaHealthChecker checks Kafka connectivity
type KafkaHealthChecker struct {
	producer interfaces.EventPublisher
}

func NewKafkaHealthChecker(producer interfaces.EventPublisher) *KafkaHealthChecker {
	return &KafkaHealthChecker{producer: producer}
}

func (k *KafkaHealthChecker) Name() string {
	return "kafka"
}

func (k *KafkaHealthChecker) Check(ctx context.Context) error {
	if k.producer == nil {
		return fmt.Errorf("kafka producer not initialized")
	}
	return k.producer.HealthCheck(ctx)
}

// HTTPHealthChecker checks HTTP service connectivity
type HTTPHealthChecker struct {
	name       string
	url        string
	timeout    time.Duration
	httpClient *http.Client
}

func NewHTTPHealthChecker(name, url string, timeout time.Duration) *HTTPHealthChecker {
	return &HTTPHealthChecker{
		name:    name,
		url:     url,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (h *HTTPHealthChecker) Name() string {
	return h.name
}

func (h *HTTPHealthChecker) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", h.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	
	return nil
}

// DatabaseHealthChecker checks database connectivity
type DatabaseHealthChecker struct {
	name string
	ping func(ctx context.Context) error
}

func NewDatabaseHealthChecker(name string, pingFunc func(ctx context.Context) error) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{
		name: name,
		ping: pingFunc,
	}
}

func (d *DatabaseHealthChecker) Name() string {
	return d.name
}

func (d *DatabaseHealthChecker) Check(ctx context.Context) error {
	if d.ping == nil {
		return fmt.Errorf("ping function not provided")
	}
	return d.ping(ctx)
}