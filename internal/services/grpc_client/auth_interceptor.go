package grpc_client

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// AuthInterceptor creates a gRPC client interceptor that forwards authorization tokens
func AuthInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Extract authorization token from context
		if token := getTokenFromContext(ctx); token != "" {
			// Create metadata with authorization header
			md := metadata.New(map[string]string{
				"authorization": "Bearer " + token,
			})
			
			// Add metadata to context
			ctx = metadata.NewOutgoingContext(ctx, md)
		}
		
		// Call the actual method
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// getTokenFromContext extracts the JWT token from various context sources
func getTokenFromContext(ctx context.Context) string {
	// Try to get token from "jwt_token" context value (set by auth middleware)
	if token, ok := ctx.Value("jwt_token").(string); ok && token != "" {
		return token
	}
	
	// Try to get token from "authorization" context value
	if auth, ok := ctx.Value("authorization").(string); ok && auth != "" {
		// Remove "Bearer " prefix if present
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
		return auth
	}
	
	// Try to get from incoming metadata (for gRPC-to-gRPC calls)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("authorization"); len(values) > 0 {
			auth := values[0]
			if strings.HasPrefix(auth, "Bearer ") {
				return strings.TrimPrefix(auth, "Bearer ")
			}
			return auth
		}
	}
	
	return ""
}