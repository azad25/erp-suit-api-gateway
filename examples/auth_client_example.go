package auth_example

import (
	"context"
	"fmt"
	"log"
	"time"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
	"erp-api-gateway/internal/services/grpc_client"
	authpb "erp-api-gateway/proto/gen/auth"
)

// RunAuthExample demonstrates how to use the authentication service client
func RunAuthExample() {
	// Create a sample configuration
	cfg := &config.GRPCConfig{
		AuthServiceAddress:        "localhost:50051",
		CRMServiceAddress:         "localhost:50052",
		HRMServiceAddress:         "localhost:50053",
		FinanceServiceAddress:     "localhost:50054",
		MaxRetries:                3,
		RetryInitialInterval:      100 * time.Millisecond,
		RetryMaxInterval:          30 * time.Second,
		RetryMultiplier:           2.0,
		RetryRandomFactor:         0.1,
		MaxConnections:            10,
		ConnectTimeout:            5 * time.Second,
		MaxIdleTime:               30 * time.Minute,
		MaxConnectionAge:          2 * time.Hour,
		KeepAliveTime:             30 * time.Second,
		KeepAliveTimeout:          5 * time.Second,
		EnableHealthCheck:         true,
		HealthCheckInterval:       30 * time.Second,
		CircuitBreakerMaxRequests: 5,
		CircuitBreakerInterval:    30 * time.Second,
		CircuitBreakerTimeout:     60 * time.Second,
	}

	// Initialize logger
	logger := logging.NewNoOpLogger()

	// Create gRPC client
	client, err := grpc_client.NewGRPCClient(cfg, logger)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer client.Close()

	fmt.Println("gRPC Client Authentication Example")
	fmt.Println("==================================")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get Auth Service client
	authClient, err := client.AuthService(ctx)
	if err != nil {
		log.Fatalf("Failed to get Auth Service client: %v", err)
	}

	// Demonstrate login
	fmt.Println("\n1. Login Example:")
	loginReq := &authpb.LoginRequest{
		Email:      "admin@example.com",
		Password:   "password123",
		RememberMe: true,
	}

	var loginResp *authpb.LoginResponse
	err = client.CallWithRetry(ctx, "auth", func() error {
		var callErr error
		loginResp, callErr = authClient.Login(ctx, loginReq)
		return callErr
	})

	if err != nil {
		fmt.Printf("   Login failed: %v\n", err)
	} else if !loginResp.Success {
		fmt.Printf("   Login failed: %s\n", loginResp.Message)
		if len(loginResp.Errors) > 0 {
			fmt.Println("   Validation errors:")
			for field, fieldErrors := range loginResp.Errors {
				fmt.Printf("     %s: %v\n", field, fieldErrors.Errors)
			}
		}
	} else {
		fmt.Println("   Login successful!")
		fmt.Printf("   User: %s %s (%s)\n",
			loginResp.Data.User.FirstName,
			loginResp.Data.User.LastName,
			loginResp.Data.User.Email)
		fmt.Printf("   Access Token: %s...\n", loginResp.Data.AccessToken[:20])
		fmt.Printf("   Refresh Token: %s...\n", loginResp.Data.RefreshToken[:20])
		fmt.Printf("   Expires In: %d seconds\n", loginResp.Data.ExpiresIn)
		fmt.Printf("   Roles: %v\n", loginResp.Data.User.Roles)
		fmt.Printf("   Permissions: %v\n", loginResp.Data.User.Permissions)
	}

	// If login was successful, demonstrate token validation
	if loginResp != nil && loginResp.Success {
		fmt.Println("\n2. Token Validation Example:")
		validateReq := &authpb.ValidateTokenRequest{
			Token: loginResp.Data.AccessToken,
		}

		var validateResp *authpb.ValidateTokenResponse
		err = client.CallWithRetry(ctx, "auth", func() error {
			var callErr error
			validateResp, callErr = authClient.ValidateToken(ctx, validateReq)
			return callErr
		})

		if err != nil {
			fmt.Printf("   Token validation failed: %v\n", err)
		} else if !validateResp.Valid {
			fmt.Printf("   Token is invalid: %s\n", validateResp.Error)
		} else {
			fmt.Println("   Token is valid!")
			fmt.Printf("   User ID: %s\n", validateResp.Claims.UserId)
			fmt.Printf("   Email: %s\n", validateResp.Claims.Email)
			fmt.Printf("   Roles: %v\n", validateResp.Claims.Roles)
			fmt.Printf("   Permissions: %v\n", validateResp.Claims.Permissions)
			fmt.Printf("   Expires At: %d\n", validateResp.Claims.ExpiresAt)
		}

		// Demonstrate token refresh
		fmt.Println("\n3. Token Refresh Example:")
		refreshReq := &authpb.RefreshTokenRequest{
			RefreshToken: loginResp.Data.RefreshToken,
		}

		var refreshResp *authpb.RefreshTokenResponse
		err = client.CallWithRetry(ctx, "auth", func() error {
			var callErr error
			refreshResp, callErr = authClient.RefreshToken(ctx, refreshReq)
			return callErr
		})

		if err != nil {
			fmt.Printf("   Token refresh failed: %v\n", err)
		} else if !refreshResp.Success {
			fmt.Printf("   Token refresh failed: %s\n", refreshResp.Message)
		} else {
			fmt.Println("   Token refresh successful!")
			fmt.Printf("   New Access Token: %s...\n", refreshResp.Data.AccessToken[:20])
			fmt.Printf("   New Refresh Token: %s...\n", refreshResp.Data.RefreshToken[:20])
			fmt.Printf("   Expires In: %d seconds\n", refreshResp.Data.ExpiresIn)
		}

		// Demonstrate token revocation
		fmt.Println("\n4. Token Revocation Example:")
		revokeReq := &authpb.RevokeTokenRequest{
			Token: loginResp.Data.RefreshToken,
		}

		var revokeResp *authpb.RevokeTokenResponse
		err = client.CallWithRetry(ctx, "auth", func() error {
			var callErr error
			revokeResp, callErr = authClient.RevokeToken(ctx, revokeReq)
			return callErr
		})

		if err != nil {
			fmt.Printf("   Token revocation failed: %v\n", err)
		} else if !revokeResp.Success {
			fmt.Printf("   Token revocation failed: %s\n", revokeResp.Message)
		} else {
			fmt.Println("   Token revocation successful!")
		}
	}

	// Demonstrate user registration
	fmt.Println("\n5. User Registration Example:")
	registerReq := &authpb.RegisterRequest{
		FirstName:            "John",
		LastName:             "Doe",
		Email:                "john.doe@example.com",
		Password:             "securePassword123",
		PasswordConfirmation: "securePassword123",
	}

	var registerResp *authpb.RegisterResponse
	err = client.CallWithRetry(ctx, "auth", func() error {
		var callErr error
		registerResp, callErr = authClient.Register(ctx, registerReq)
		return callErr
	})

	if err != nil {
		fmt.Printf("   Registration failed: %v\n", err)
	} else if !registerResp.Success {
		fmt.Printf("   Registration failed: %s\n", registerResp.Message)
		if len(registerResp.Errors) > 0 {
			fmt.Println("   Validation errors:")
			for field, fieldErrors := range registerResp.Errors {
				fmt.Printf("     %s: %v\n", field, fieldErrors.Errors)
			}
		}
	} else {
		fmt.Println("   Registration successful!")
		fmt.Printf("   User: %s %s (%s)\n",
			registerResp.Data.User.FirstName,
			registerResp.Data.User.LastName,
			registerResp.Data.User.Email)
		fmt.Printf("   Access Token: %s...\n", registerResp.Data.AccessToken[:20])
	}

	fmt.Println("\n✅ gRPC Client Authentication Example completed successfully!")
}
