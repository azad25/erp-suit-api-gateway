package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"erp-api-gateway/internal/interfaces"
	authpb "erp-api-gateway/proto"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	grpcClient    GRPCClientInterface
	cacheService  interfaces.CacheService
	eventPublisher interfaces.EventPublisher
	logger        interfaces.SimpleLogger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
	grpcClient GRPCClientInterface,
	cacheService interfaces.CacheService,
	eventPublisher interfaces.EventPublisher,
	logger interfaces.SimpleLogger,
) *AuthHandler {
	return &AuthHandler{
		grpcClient:    grpcClient,
		cacheService:  cacheService,
		eventPublisher: eventPublisher,
		logger:        logger,
	}
}

// Login handles user login requests
// POST /auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.handleValidationError(c, err)
		return
	}

	ctx := c.Request.Context()
	
	// Get auth service client
	authClient, err := h.grpcClient.AuthService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get auth service client", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(
			"Authentication service is currently unavailable",
			nil,
		))
		return
	}

	// Create gRPC authenticate request
	grpcReq := &authpb.AuthenticateRequest{
		Email:      req.Email,
		Password:   req.Password,
		RememberMe: req.RememberMe,
		SecurityContext: &authpb.SecurityContext{
			IpAddress:  c.ClientIP(),
			UserAgent:  c.GetHeader("User-Agent"),
			SessionId:  c.GetHeader("X-Session-ID"),
		},
	}

	// Call auth service
	grpcResp, err := authClient.Authenticate(ctx, grpcReq)
	if err != nil {
		h.logger.LogError(ctx, "Auth service login failed", map[string]interface{}{
			"email": req.Email,
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, NewErrorResponse(
			"Login failed due to internal error",
			nil,
		))
		return
	}

	// Handle unsuccessful login
	if !grpcResp.Success {
		if grpcResp.Error != "" {
			c.JSON(http.StatusUnauthorized, NewErrorResponse(grpcResp.Error, nil))
		} else {
			c.JSON(http.StatusUnauthorized, NewErrorResponse("Authentication failed", nil))
		}
		return
	}

	// Convert gRPC response to HTTP response
	authData := h.convertAuthenticateData(grpcResp)
	
	// Cache user profile for performance
	if err := h.cacheUserProfile(ctx, authData.User); err != nil {
		h.logger.LogError(ctx, "Failed to cache user profile", map[string]interface{}{
			"user_id": authData.User.ID,
			"error":   err.Error(),
		})
	}

	// Publish login event
	if err := h.publishLoginEvent(ctx, authData.User.ID, req.Email); err != nil {
		h.logger.LogError(ctx, "Failed to publish login event", map[string]interface{}{
			"user_id": authData.User.ID,
			"error":   err.Error(),
		})
	}

	h.logger.LogInfo(ctx, "User logged in successfully", map[string]interface{}{
		"user_id": authData.User.ID,
		"email":   req.Email,
	})

	c.JSON(http.StatusOK, NewSuccessResponse(authData, "Login successful"))
}

// Register handles user registration requests
// POST /auth/register/
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.handleValidationError(c, err)
		return
	}

	ctx := c.Request.Context()

	// Validate password confirmation
	if req.Password != req.PasswordConfirmation {
		c.JSON(http.StatusBadRequest, NewErrorResponse(
			"Validation failed",
			map[string][]string{
				"password_confirmation": {"Password confirmation does not match"},
			},
		))
		return
	}

	// Get auth service client
	authClient, err := h.grpcClient.AuthService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get auth service client", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(
			"Authentication service is currently unavailable",
			nil,
		))
		return
	}

	// Create gRPC create organization request (which creates both org and admin user)
	grpcReq := &authpb.CreateOrganizationRequest{
		Name:           req.OrganizationName,
		Domain:         req.Domain,
		AdminEmail:     req.Email,
		AdminPassword:  req.Password,
		AdminFirstName: req.FirstName,
		AdminLastName:  req.LastName,
		SecurityContext: &authpb.SecurityContext{
			IpAddress: c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			SessionId: c.GetHeader("X-Session-ID"),
		},
	}

	// Call auth service
	grpcResp, err := authClient.CreateOrganization(ctx, grpcReq)
	if err != nil {
		h.logger.LogError(ctx, "Auth service register failed", map[string]interface{}{
			"email": req.Email,
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, NewErrorResponse(
			"Registration failed due to internal error",
			nil,
		))
		return
	}

	// Handle unsuccessful registration
	if !grpcResp.Success {
		if grpcResp.Error != "" {
			c.JSON(http.StatusBadRequest, NewErrorResponse(grpcResp.Error, nil))
		} else {
			c.JSON(http.StatusBadRequest, NewErrorResponse("Registration failed", nil))
		}
		return
	}

	// Convert gRPC response to HTTP response
	authData := h.convertCreateOrganizationData(grpcResp)

	// Cache user profile for performance
	if err := h.cacheUserProfile(ctx, authData.User); err != nil {
		h.logger.LogError(ctx, "Failed to cache user profile", map[string]interface{}{
			"user_id": authData.User.ID,
			"error":   err.Error(),
		})
	}

	// Publish registration event
	if err := h.publishRegistrationEvent(ctx, authData.User.ID, req.Email); err != nil {
		h.logger.LogError(ctx, "Failed to publish registration event", map[string]interface{}{
			"user_id": authData.User.ID,
			"error":   err.Error(),
		})
	}

	h.logger.LogInfo(ctx, "User registered successfully", map[string]interface{}{
		"user_id": authData.User.ID,
		"email":   req.Email,
	})

	c.JSON(http.StatusCreated, NewSuccessResponse(authData, "Registration successful"))
}

// Logout handles user logout requests
// POST /auth/logout/
func (h *AuthHandler) Logout(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, NewErrorResponse("User not authenticated", nil))
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, NewErrorResponse("Invalid user context", nil))
		return
	}

	// Get token from Authorization header
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse("Authorization token required", nil))
		return
	}

	// Remove "Bearer " prefix
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	// Get auth service client
	authClient, err := h.grpcClient.AuthService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get auth service client", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(
			"Authentication service is currently unavailable",
			nil,
		))
		return
	}

	// Create gRPC revoke token request
	grpcReq := &authpb.RevokeTokenRequest{
		Token: token,
	}

	// Call auth service to revoke token
	grpcResp, err := authClient.RevokeToken(ctx, grpcReq)
	if err != nil {
		h.logger.LogError(ctx, "Auth service revoke token failed", map[string]interface{}{
			"user_id": userIDStr,
			"error":   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, NewErrorResponse(
			"Logout failed due to internal error",
			nil,
		))
		return
	}

	// Clear cached user data
	h.clearUserCache(ctx, userIDStr)

	// Publish logout event
	if err := h.publishLogoutEvent(ctx, userIDStr); err != nil {
		h.logger.LogError(ctx, "Failed to publish logout event", map[string]interface{}{
			"user_id": userIDStr,
			"error":   err.Error(),
		})
	}

	h.logger.LogInfo(ctx, "User logged out successfully", map[string]interface{}{
		"user_id": userIDStr,
	})

	if grpcResp.Success {
		c.JSON(http.StatusOK, NewSuccessResponse(nil, "Logout successful"))
	} else {
		c.JSON(http.StatusInternalServerError, NewErrorResponse("Logout failed", nil))
	}
}

// RefreshToken handles token refresh requests
// POST /auth/refresh/
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.handleValidationError(c, err)
		return
	}

	ctx := c.Request.Context()

	// Get auth service client
	authClient, err := h.grpcClient.AuthService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get auth service client", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(
			"Authentication service is currently unavailable",
			nil,
		))
		return
	}

	// Create gRPC refresh token request
	grpcReq := &authpb.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	// Call auth service
	grpcResp, err := authClient.RefreshToken(ctx, grpcReq)
	if err != nil {
		h.logger.LogError(ctx, "Auth service refresh token failed", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, NewErrorResponse(
			"Token refresh failed due to internal error",
			nil,
		))
		return
	}

	// Handle unsuccessful refresh
	if grpcResp.Error != "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(grpcResp.Error, nil))
		return
	}

	// Convert gRPC response to HTTP response
	tokenPair := &TokenPair{
		AccessToken:  grpcResp.AccessToken,
		RefreshToken: grpcResp.RefreshToken,
		ExpiresIn:    int64(grpcResp.ExpiresIn),
	}

	// Publish token refresh event
	if userID, exists := c.Get("user_id"); exists {
		if userIDStr, ok := userID.(string); ok {
			if err := h.publishTokenRefreshEvent(ctx, userIDStr); err != nil {
				h.logger.LogError(ctx, "Failed to publish token refresh event", map[string]interface{}{
					"user_id": userIDStr,
					"error":   err.Error(),
				})
			}
		}
	}

	c.JSON(http.StatusOK, NewSuccessResponse(tokenPair, "Token refreshed successfully"))
}

// GetCurrentUser handles current user info requests
// GET /auth/me/
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, NewErrorResponse("User not authenticated", nil))
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, NewErrorResponse("Invalid user context", nil))
		return
	}

	// Try to get user from cache first
	if cachedUser, err := h.getCachedUserProfile(ctx, userIDStr); err == nil {
		c.JSON(http.StatusOK, NewSuccessResponse(cachedUser, "User profile retrieved"))
		return
	}

	// Get auth service client
	authClient, err := h.grpcClient.AuthService(ctx)
	if err != nil {
		h.logger.LogError(ctx, "Failed to get auth service client", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(
			"Authentication service is currently unavailable",
			nil,
		))
		return
	}

	// Create gRPC get user request
	grpcReq := &authpb.GetUserRequest{
		UserId: userIDStr,
	}

	// Call auth service
	grpcResp, err := authClient.GetUser(ctx, grpcReq)
	if err != nil {
		h.logger.LogError(ctx, "Auth service get user failed", map[string]interface{}{
			"user_id": userIDStr,
			"error":   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, NewErrorResponse(
			"Failed to retrieve user information",
			nil,
		))
		return
	}

	// Handle unsuccessful response
	if grpcResp.Error != "" {
		c.JSON(http.StatusNotFound, NewErrorResponse(grpcResp.Error, nil))
		return
	}

	// Convert gRPC user to HTTP user
	user := h.convertUser(grpcResp.User)

	// Cache user profile for future requests
	if err := h.cacheUserProfile(ctx, user); err != nil {
		h.logger.LogError(ctx, "Failed to cache user profile", map[string]interface{}{
			"user_id": userIDStr,
			"error":   err.Error(),
		})
	}

	c.JSON(http.StatusOK, NewSuccessResponse(user, "User profile retrieved"))
}

// Helper methods

// handleValidationError handles validation errors from Gin binding
func (h *AuthHandler) handleValidationError(c *gin.Context, err error) {
	var validationErrors []ValidationError
	
	// Convert Gin validation errors to our format
	// This is a simplified version - in production, you'd want more sophisticated error parsing
	validationErrors = append(validationErrors, ValidationError{
		Field:   "validation",
		Message: err.Error(),
	})

	c.JSON(http.StatusBadRequest, NewValidationErrorResponse(validationErrors))
}

// convertGRPCErrors converts gRPC field errors to HTTP format
// convertGRPCErrors is no longer needed as the new auth service uses simple error strings
// This method is kept for backward compatibility but returns empty map
func (h *AuthHandler) convertGRPCErrors(grpcErrors interface{}) map[string][]string {
	// The new auth service uses simple error strings instead of structured field errors
	return make(map[string][]string)
}

// convertAuthenticateData converts gRPC AuthenticateResponse to HTTP AuthData
func (h *AuthHandler) convertAuthenticateData(grpcResp *authpb.AuthenticateResponse) *AuthData {
	if grpcResp == nil || grpcResp.Tokens == nil {
		return nil
	}

	return &AuthData{
		User:         h.convertUser(grpcResp.User),
		AccessToken:  grpcResp.Tokens.AccessToken,
		RefreshToken: grpcResp.Tokens.RefreshToken,
		ExpiresIn:    int64(3600), // Default to 1 hour, could be calculated from expires_at
	}
}

// convertCreateOrganizationData converts gRPC CreateOrganizationResponse to HTTP AuthData
func (h *AuthHandler) convertCreateOrganizationData(grpcResp *authpb.CreateOrganizationResponse) *AuthData {
	if grpcResp == nil || grpcResp.Tokens == nil {
		return nil
	}

	return &AuthData{
		User:         h.convertUser(grpcResp.AdminUser),
		AccessToken:  grpcResp.Tokens.AccessToken,
		RefreshToken: grpcResp.Tokens.RefreshToken,
		ExpiresIn:    int64(3600), // Default to 1 hour, could be calculated from expires_at
	}
}

// convertAuthData is a legacy method that's no longer used
// The new auth service uses different response structures handled by
// convertAuthenticateData and convertCreateOrganizationData methods

// convertTokenPair converts gRPC TokenPair to HTTP TokenPair
func (h *AuthHandler) convertTokenPair(grpcData *authpb.TokenPair) *TokenPair {
	if grpcData == nil {
		return nil
	}

	// Calculate expires_in from expires_at timestamp
	expiresIn := int64(3600) // Default to 1 hour
	if grpcData.ExpiresAt != nil {
		expiresIn = grpcData.ExpiresAt.AsTime().Unix() - time.Now().Unix()
		if expiresIn < 0 {
			expiresIn = 0
		}
	}

	return &TokenPair{
		AccessToken:  grpcData.AccessToken,
		RefreshToken: grpcData.RefreshToken,
		ExpiresIn:    expiresIn,
	}
}

// convertUser converts gRPC User to HTTP User
func (h *AuthHandler) convertUser(grpcUser *authpb.User) User {
	if grpcUser == nil {
		return User{}
	}

	user := User{
		ID:        grpcUser.Id,
		FirstName: grpcUser.FirstName,
		LastName:  grpcUser.LastName,
		Email:     grpcUser.Email,
		CreatedAt: grpcUser.CreatedAt.AsTime(),
		UpdatedAt: grpcUser.UpdatedAt.AsTime(),
	}

	// The new User struct doesn't have EmailVerifiedAt field
	// Email verification status is now handled through the is_verified boolean field
	// which is already included in the User struct

	return user
}

// cacheUserProfile caches user profile data
func (h *AuthHandler) cacheUserProfile(ctx context.Context, user User) error {
	cacheKey := fmt.Sprintf(CacheKeyUserProfile, user.ID)
	
	userData, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	return h.cacheService.Set(ctx, cacheKey, userData, CacheTTLUserProfile)
}

// getCachedUserProfile retrieves cached user profile data
func (h *AuthHandler) getCachedUserProfile(ctx context.Context, userID string) (*User, error) {
	cacheKey := fmt.Sprintf(CacheKeyUserProfile, userID)
	
	userData, err := h.cacheService.Get(ctx, cacheKey)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(userData, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached user data: %w", err)
	}

	return &user, nil
}

// clearUserCache clears all cached data for a user
func (h *AuthHandler) clearUserCache(ctx context.Context, userID string) {
	cacheKeys := []string{
		fmt.Sprintf(CacheKeyUserProfile, userID),
		fmt.Sprintf(CacheKeyUserPermissions, userID),
		fmt.Sprintf(CacheKeyUserRoles, userID),
	}

	for _, key := range cacheKeys {
		if err := h.cacheService.Delete(ctx, key); err != nil {
			h.logger.LogError(ctx, "Failed to clear cache key", map[string]interface{}{
				"key":   key,
				"error": err.Error(),
			})
		}
	}
}

// Event publishing methods

// publishLoginEvent publishes a user login event
func (h *AuthHandler) publishLoginEvent(ctx context.Context, userID, email string) error {
	event := interfaces.Event{
		ID:            uuid.New().String(),
		Type:          interfaces.EventTypeUserLoggedIn,
		UserID:        userID,
		Data: map[string]interface{}{
			"email":      email,
			"login_time": time.Now().UTC(),
			"ip_address": h.getClientIP(ctx),
			"user_agent": h.getUserAgent(ctx),
		},
		Timestamp:     time.Now().UTC(),
		CorrelationID: h.getCorrelationID(ctx),
		Source:        "api-gateway",
		Version:       "1.0",
	}

	return h.eventPublisher.PublishUserEvent(ctx, userID, event)
}

// publishRegistrationEvent publishes a user registration event
func (h *AuthHandler) publishRegistrationEvent(ctx context.Context, userID, email string) error {
	event := interfaces.Event{
		ID:            uuid.New().String(),
		Type:          interfaces.EventTypeUserRegistered,
		UserID:        userID,
		Data: map[string]interface{}{
			"email":             email,
			"registration_time": time.Now().UTC(),
			"ip_address":        h.getClientIP(ctx),
			"user_agent":        h.getUserAgent(ctx),
		},
		Timestamp:     time.Now().UTC(),
		CorrelationID: h.getCorrelationID(ctx),
		Source:        "api-gateway",
		Version:       "1.0",
	}

	return h.eventPublisher.PublishUserEvent(ctx, userID, event)
}

// publishLogoutEvent publishes a user logout event
func (h *AuthHandler) publishLogoutEvent(ctx context.Context, userID string) error {
	event := interfaces.Event{
		ID:            uuid.New().String(),
		Type:          interfaces.EventTypeUserLoggedOut,
		UserID:        userID,
		Data: map[string]interface{}{
			"logout_time": time.Now().UTC(),
			"ip_address":  h.getClientIP(ctx),
			"user_agent":  h.getUserAgent(ctx),
		},
		Timestamp:     time.Now().UTC(),
		CorrelationID: h.getCorrelationID(ctx),
		Source:        "api-gateway",
		Version:       "1.0",
	}

	return h.eventPublisher.PublishUserEvent(ctx, userID, event)
}

// publishTokenRefreshEvent publishes a token refresh event
func (h *AuthHandler) publishTokenRefreshEvent(ctx context.Context, userID string) error {
	event := interfaces.Event{
		ID:            uuid.New().String(),
		Type:          interfaces.EventTypeTokenRefreshed,
		UserID:        userID,
		Data: map[string]interface{}{
			"refresh_time": time.Now().UTC(),
			"ip_address":   h.getClientIP(ctx),
			"user_agent":   h.getUserAgent(ctx),
		},
		Timestamp:     time.Now().UTC(),
		CorrelationID: h.getCorrelationID(ctx),
		Source:        "api-gateway",
		Version:       "1.0",
	}

	return h.eventPublisher.PublishUserEvent(ctx, userID, event)
}

// Utility methods for extracting request context

// getClientIP extracts client IP from context
func (h *AuthHandler) getClientIP(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		return ginCtx.ClientIP()
	}
	return "unknown"
}

// getUserAgent extracts user agent from context
func (h *AuthHandler) getUserAgent(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		return ginCtx.GetHeader("User-Agent")
	}
	return "unknown"
}

// getCorrelationID extracts or generates correlation ID from context
func (h *AuthHandler) getCorrelationID(ctx context.Context) string {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		if correlationID := ginCtx.GetHeader("X-Correlation-ID"); correlationID != "" {
			return correlationID
		}
		if correlationID := ginCtx.GetHeader("X-Request-ID"); correlationID != "" {
			return correlationID
		}
	}
	return uuid.New().String()
}