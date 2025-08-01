package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// MockCacheService is a mock implementation of CacheService
type MockCacheService struct {
	mock.Mock
}

func (m *MockCacheService) Get(ctx context.Context, key string) ([]byte, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCacheService) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	args := m.Called(ctx, key, value, ttl)
	return args.Error(0)
}

func (m *MockCacheService) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockCacheService) Exists(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockCacheService) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	args := m.Called(ctx, key, value, ttl)
	return args.Bool(0), args.Error(1)
}

func (m *MockCacheService) Increment(ctx context.Context, key string) (int64, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockCacheService) Expire(ctx context.Context, key string, ttl time.Duration) error {
	args := m.Called(ctx, key, ttl)
	return args.Error(0)
}

// Test helper functions
func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createTestJWKS(publicKey *rsa.PublicKey, keyID string) (string, error) {
	key, err := jwk.FromRaw(publicKey)
	if err != nil {
		return "", err
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return "", err
	}

	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return "", err
	}

	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return "", err
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return "", err
	}

	jwksBytes, err := json.Marshal(set)
	if err != nil {
		return "", err
	}

	return string(jwksBytes), nil
}

func createTestToken(privateKey *rsa.PrivateKey, keyID string, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(privateKey)
}

func TestJWTValidator_ValidateToken(t *testing.T) {
	// Generate test keys
	privateKey, publicKey, err := generateRSAKeyPair()
	assert.NoError(t, err)

	keyID := "test-key-id"
	issuer := "test-issuer"

	// Create JWKS server
	jwksData, err := createTestJWKS(publicKey, keyID)
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksData))
	}))
	defer server.Close()

	// Create test configuration
	cfg := &config.JWTConfig{
		JWKSUrl:   server.URL,
		Algorithm: "RS256",
		Issuer:    issuer,
		CacheTTL:  time.Hour,
	}

	// Create mock cache
	mockCache := new(MockCacheService)
	mockCache.On("Get", mock.Anything, mock.AnythingOfType("string")).Return([]byte{}, interfaces.ErrCacheKeyNotFound)
	mockCache.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)

	// Create validator
	validator := NewJWTValidator(cfg, mockCache)

	t.Run("ValidToken", func(t *testing.T) {
		// Create valid token
		claims := jwt.MapClaims{
			"user_id":     "test-user-id",
			"email":       "test@example.com",
			"roles":       []string{"user", "admin"},
			"permissions": []string{"read", "write"},
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iat":         time.Now().Unix(),
			"iss":         issuer,
			"sub":         "test-user-id",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Validate token
		userClaims, err := validator.ValidateToken(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, userClaims)
		assert.Equal(t, "test-user-id", userClaims.UserID)
		assert.Equal(t, "test@example.com", userClaims.Email)
		assert.Equal(t, []string{"user", "admin"}, userClaims.Roles)
		assert.Equal(t, []string{"read", "write"}, userClaims.Permissions)
		assert.Equal(t, issuer, userClaims.Issuer)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		// Create expired token
		claims := jwt.MapClaims{
			"user_id": "test-user-id",
			"email":   "test@example.com",
			"exp":     time.Now().Add(-time.Hour).Unix(), // Expired
			"iat":     time.Now().Add(-2 * time.Hour).Unix(),
			"iss":     issuer,
			"sub":     "test-user-id",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Validate token
		userClaims, err := validator.ValidateToken(tokenString)
		assert.Error(t, err)
		assert.Nil(t, userClaims)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("InvalidIssuer", func(t *testing.T) {
		// Create token with wrong issuer
		claims := jwt.MapClaims{
			"user_id": "test-user-id",
			"email":   "test@example.com",
			"exp":     time.Now().Add(time.Hour).Unix(),
			"iat":     time.Now().Unix(),
			"iss":     "wrong-issuer",
			"sub":     "test-user-id",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Validate token
		userClaims, err := validator.ValidateToken(tokenString)
		assert.Error(t, err)
		assert.Nil(t, userClaims)
		assert.Contains(t, err.Error(), "invalid issuer")
	})

	t.Run("MissingUserID", func(t *testing.T) {
		// Create token without user_id
		claims := jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"iss":   issuer,
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Validate token
		userClaims, err := validator.ValidateToken(tokenString)
		assert.Error(t, err)
		assert.Nil(t, userClaims)
		assert.Contains(t, err.Error(), "missing user_id")
	})

	mockCache.AssertExpectations(t)
}

func TestJWTValidator_GetPublicKey(t *testing.T) {
	// Generate test keys
	_, publicKey, err := generateRSAKeyPair()
	assert.NoError(t, err)

	keyID := "test-key-id"

	// Create JWKS server
	jwksData, err := createTestJWKS(publicKey, keyID)
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksData))
	}))
	defer server.Close()

	// Create test configuration
	cfg := &config.JWTConfig{
		JWKSUrl:   server.URL,
		Algorithm: "RS256",
		CacheTTL:  time.Hour,
	}

	// Create validator
	validator := NewJWTValidator(cfg, nil)

	t.Run("ValidKeyID", func(t *testing.T) {
		key, err := validator.GetPublicKey(keyID)
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, publicKey.N, key.N)
		assert.Equal(t, publicKey.E, key.E)
	})

	t.Run("InvalidKeyID", func(t *testing.T) {
		key, err := validator.GetPublicKey("invalid-key-id")
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestJWTValidator_RefreshJWKS(t *testing.T) {
	// Generate test keys
	_, publicKey, err := generateRSAKeyPair()
	assert.NoError(t, err)

	keyID := "test-key-id"

	// Create JWKS server
	jwksData, err := createTestJWKS(publicKey, keyID)
	assert.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksData))
	}))
	defer server.Close()

	// Create test configuration
	cfg := &config.JWTConfig{
		JWKSUrl:   server.URL,
		Algorithm: "RS256",
		CacheTTL:  time.Hour,
	}

	// Create validator
	validator := NewJWTValidator(cfg, nil)

	t.Run("SuccessfulRefresh", func(t *testing.T) {
		err := validator.RefreshJWKS()
		assert.NoError(t, err)
		assert.NotNil(t, validator.jwksCache)
		assert.False(t, validator.lastRefresh.IsZero())
	})

	t.Run("InvalidJWKSURL", func(t *testing.T) {
		cfg.JWKSUrl = "http://invalid-url"
		validator := NewJWTValidator(cfg, nil)

		err := validator.RefreshJWKS()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch JWKS")
	})

	t.Run("EmptyJWKSURL", func(t *testing.T) {
		cfg.JWKSUrl = ""
		validator := NewJWTValidator(cfg, nil)

		err := validator.RefreshJWKS()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWKS URL not configured")
	})
}