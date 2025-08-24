package resolver

import (
	"erp-api-gateway/api/graphql/dataloader"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	Config         *config.Config
	Logger         logging.Logger
	GRPCClient     *grpc_client.GRPCClient
	RedisClient    *services.RedisClient
	EventPublisher interfaces.EventPublisher
	DataLoader     *dataloader.DataLoader
}
