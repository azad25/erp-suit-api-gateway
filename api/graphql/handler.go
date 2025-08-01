package graphql

import (
	"context"
	"net/http"
	"strings"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"erp-api-gateway/api/graphql/dataloader"
	"erp-api-gateway/api/graphql/generated"
	"erp-api-gateway/api/graphql/resolver"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services"
	"erp-api-gateway/internal/services/grpc_client"
)

// GraphQLHandler handles GraphQL requests
type GraphQLHandler struct {
	config        *config.Config
	logger        logging.Logger
	grpcClient    *grpc_client.GRPCClient
	redisClient   *services.RedisClient
	kafkaProducer *services.KafkaProducer
	dataLoader    *dataloader.DataLoader
	server        *handler.Server
}

// NewGraphQLHandler creates a new GraphQL handler
func NewGraphQLHandler(
	cfg *config.Config,
	logger logging.Logger,
	grpcClient *grpc_client.GRPCClient,
	redisClient *services.RedisClient,
	kafkaProducer *services.KafkaProducer,
) *GraphQLHandler {
	// Create DataLoader
	dl := dataloader.NewDataLoader(grpcClient)
	
	// Create resolver with dependencies
	resolver := &resolver.Resolver{
		Config:        cfg,
		Logger:        logger,
		GRPCClient:    grpcClient,
		RedisClient:   redisClient,
		KafkaProducer: kafkaProducer,
		DataLoader:    dl,
	}
	
	// Create GraphQL server
	srv := handler.New(generated.NewExecutableSchema(generated.Config{
		Resolvers: resolver,
	}))
	
	// Configure server
	srv.AddTransport(transport.Websocket{
		KeepAlivePingInterval: 10,
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Check against allowed origins
				origin := r.Header.Get("Origin")
				for _, allowedOrigin := range cfg.Server.CORS.AllowedOrigins {
					if origin == allowedOrigin {
						return true
					}
				}
				// Allow localhost for development
				return strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1")
			},
		},
	})
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.AddTransport(transport.MultipartForm{})
	
	// Add query complexity analysis
	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{
		Cache: lru.New[string](100),
	})
	
	// Add query complexity limits
	srv.Use(extension.FixedComplexityLimit(1000))
	
	return &GraphQLHandler{
		config:        cfg,
		logger:        logger,
		grpcClient:    grpcClient,
		redisClient:   redisClient,
		kafkaProducer: kafkaProducer,
		dataLoader:    dl,
		server:        srv,
	}
}

// ServeHTTP handles GraphQL HTTP requests
func (h *GraphQLHandler) ServeHTTP() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add DataLoader to context
		ctx := context.WithValue(c.Request.Context(), "dataloader", h.dataLoader)
		c.Request = c.Request.WithContext(ctx)
		
		// Add user context if authenticated
		if userID, exists := c.Get("user_id"); exists {
			ctx = context.WithValue(ctx, "user_id", userID)
			c.Request = c.Request.WithContext(ctx)
		}
		
		if userClaims, exists := c.Get("user_claims"); exists {
			ctx = context.WithValue(ctx, "user_claims", userClaims)
			c.Request = c.Request.WithContext(ctx)
		}
		
		// Serve GraphQL
		h.server.ServeHTTP(c.Writer, c.Request)
	}
}

// PlaygroundHandler serves the GraphQL Playground
func (h *GraphQLHandler) PlaygroundHandler() gin.HandlerFunc {
	playgroundHandler := playground.Handler("GraphQL Playground", "/graphql")
	return func(c *gin.Context) {
		playgroundHandler.ServeHTTP(c.Writer, c.Request)
	}
}

// GetDataLoaderFromContext retrieves the DataLoader from context
func GetDataLoaderFromContext(ctx context.Context) *dataloader.DataLoader {
	if dl, ok := ctx.Value("dataloader").(*dataloader.DataLoader); ok {
		return dl
	}
	return nil
}

// GetUserIDFromContext retrieves the user ID from context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID, true
	}
	return "", false
}

// GetUserClaimsFromContext retrieves user claims from context
func GetUserClaimsFromContext(ctx context.Context) interface{} {
	return ctx.Value("user_claims")
}