package interfaces

import (
	"context"
	"crypto/rsa"
)

// JWTValidator defines the interface for JWT token validation
type JWTValidator interface {
	ValidateToken(token string) (*Claims, error)
	GetPublicKey(keyID string) (*rsa.PublicKey, error)
	RefreshJWKS() error
}

// Claims represents the JWT token claims
type Claims struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	ExpiresAt   int64    `json:"exp"`
	IssuedAt    int64    `json:"iat"`
	Subject     string   `json:"sub"`
	Issuer      string   `json:"iss"`
}

// AuthService defines the interface for authentication operations
type AuthService interface {
	ValidateCredentials(ctx context.Context, email, password string) (*Claims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
	RevokeToken(ctx context.Context, token string) error
	GetUserByID(ctx context.Context, userID string) (*User, error)
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// User represents a user entity
type User struct {
	ID              string `json:"id"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Email           string `json:"email"`
	EmailVerifiedAt *int64 `json:"email_verified_at,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
}