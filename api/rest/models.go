package rest

import (
	"time"
)

// HTTP Request Models

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required,min=8"`
	RememberMe bool   `json:"remember_me"`
}

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	FirstName            string `json:"first_name" binding:"required,min=2,max=50"`
	LastName             string `json:"last_name" binding:"required,min=2,max=50"`
	Email                string `json:"email" binding:"required,email"`
	Password             string `json:"password" binding:"required,min=8"`
	PasswordConfirmation string `json:"password_confirmation" binding:"required"`
	OrganizationName     string `json:"organization_name" binding:"required,min=2,max=100"`
	Domain               string `json:"domain" binding:"required,min=2,max=100"`
}

// RefreshTokenRequest represents the refresh token request payload
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// HTTP Response Models

// APIResponse represents the standard API response format
type APIResponse struct {
	Success bool                `json:"success"`
	Message string              `json:"message,omitempty"`
	Data    interface{}         `json:"data,omitempty"`
	Errors  map[string][]string `json:"errors,omitempty"`
}

// AuthData represents authentication response data
type AuthData struct {
	User         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// TokenPair represents token pair response data
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// User represents user data in API responses
type User struct {
	ID              string     `json:"id"`
	FirstName       string     `json:"first_name"`
	LastName        string     `json:"last_name"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ErrorResponse represents error response format
type ErrorResponse struct {
	Success bool                `json:"success"`
	Message string              `json:"message"`
	Errors  map[string][]string `json:"errors,omitempty"`
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// NewSuccessResponse creates a successful API response
func NewSuccessResponse(data interface{}, message string) *APIResponse {
	return &APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// NewErrorResponse creates an error API response
func NewErrorResponse(message string, errors map[string][]string) *APIResponse {
	return &APIResponse{
		Success: false,
		Message: message,
		Errors:  errors,
	}
}

// NewValidationErrorResponse creates a validation error response
func NewValidationErrorResponse(validationErrors []ValidationError) *APIResponse {
	errors := make(map[string][]string)
	for _, err := range validationErrors {
		errors[err.Field] = append(errors[err.Field], err.Message)
	}
	
	return &APIResponse{
		Success: false,
		Message: "Validation failed",
		Errors:  errors,
	}
}

// Cache keys for response caching
const (
	CacheKeyUserProfile    = "user_profile:%s"
	CacheKeyUserPermissions = "user_permissions:%s"
	CacheKeyUserRoles      = "user_roles:%s"
)

// Cache TTL durations
const (
	CacheTTLUserProfile    = 15 * time.Minute
	CacheTTLUserPermissions = 10 * time.Minute
	CacheTTLUserRoles      = 10 * time.Minute
)