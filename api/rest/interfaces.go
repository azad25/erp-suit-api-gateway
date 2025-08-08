package rest

import (
	"context"
	authpb "erp-api-gateway/proto"
)

// GRPCClientInterface defines the interface for gRPC client operations needed by REST handlers
type GRPCClientInterface interface {
	AuthService(ctx context.Context) (authpb.AuthServiceClient, error)
}