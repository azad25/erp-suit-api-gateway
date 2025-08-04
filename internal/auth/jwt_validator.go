package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// JWTValidator implements the JWT validation interface
type JWTValidator struct {
	config      *config.JWTConfig
	cache       interfaces.CacheService
	jwksCache   jwk.Set
	jwksMutex   sync.RWMutex
	lastRefresh time.Time
	httpClient  *http.Client
}

// NewJWTValidator creates a new JWT validator instance
func NewJWTValidator(cfg *config.JWTConfig, cache interfaces.CacheService) *JWTValidator {
	return &JWTValidator{
		config: cfg,
		cache:  cache,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ValidateToken validates a JWT token and returns the claims
func (v *JWTValidator) ValidateToken(tokenString string) (*interfaces.Claims, error) {
	// Check cache first
	if v.cache != nil {
		cacheKey := fmt.Sprintf("jwt:validated:%s", tokenString)
		if cachedData, err := v.cache.Get(context.Background(), cacheKey); err == nil {
			var claims interfaces.Claims
			if err := json.Unmarshal(cachedData, &claims); err == nil {
				// Check if token is still valid (not expired)
				if time.Now().Unix() < claims.ExpiresAt {
					return &claims, nil
				}
				// Remove expired token from cache
				v.cache.Delete(context.Background(), cacheKey)
			}
		}
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if token.Method.Alg() != v.config.Algorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Handle different signing methods
		switch v.config.Algorithm {
		case "HS256", "HS384", "HS512":
			// HMAC signing method - use shared secret
			if v.config.Secret == "" {
				return nil, fmt.Errorf("JWT secret not configured for HMAC signing")
			}
			return []byte(v.config.Secret), nil
			
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
			// RSA/ECDSA signing method - use public key from JWKS
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("missing key ID in token header")
			}
			return v.GetPublicKey(keyID)
			
		default:
			return nil, fmt.Errorf("unsupported signing method: %s", v.config.Algorithm)
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Validate token claims
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Convert to our Claims struct
	userClaims, err := v.mapClaimsToStruct(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to map claims: %w", err)
	}

	// Validate issuer if configured
	if v.config.Issuer != "" && userClaims.Issuer != v.config.Issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.config.Issuer, userClaims.Issuer)
	}

	// Cache the validated token
	if v.cache != nil {
		cacheKey := fmt.Sprintf("jwt:validated:%s", tokenString)
		if claimsData, err := json.Marshal(userClaims); err == nil {
			// Cache until token expires
			ttl := time.Until(time.Unix(userClaims.ExpiresAt, 0))
			if ttl > 0 {
				v.cache.Set(context.Background(), cacheKey, claimsData, ttl)
			}
		}
	}

	return userClaims, nil
}

// GetPublicKey retrieves the public key for the given key ID
func (v *JWTValidator) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	// Refresh JWKS if needed
	if err := v.refreshJWKSIfNeeded(); err != nil {
		return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
	}

	v.jwksMutex.RLock()
	defer v.jwksMutex.RUnlock()

	if v.jwksCache == nil {
		return nil, fmt.Errorf("JWKS not loaded")
	}

	// Find the key with the matching key ID
	key, found := v.jwksCache.LookupKeyID(keyID)
	if !found {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}

	// Convert to RSA public key
	var rsaKey rsa.PublicKey
	if err := key.Raw(&rsaKey); err != nil {
		return nil, fmt.Errorf("failed to convert key to RSA: %w", err)
	}

	return &rsaKey, nil
}

// RefreshJWKS manually refreshes the JWKS cache
func (v *JWTValidator) RefreshJWKS() error {
	return v.refreshJWKS()
}

// refreshJWKSIfNeeded refreshes JWKS if the cache is stale
func (v *JWTValidator) refreshJWKSIfNeeded() error {
	v.jwksMutex.RLock()
	needsRefresh := v.jwksCache == nil || time.Since(v.lastRefresh) > v.config.CacheTTL
	v.jwksMutex.RUnlock()

	if needsRefresh {
		return v.refreshJWKS()
	}

	return nil
}

// refreshJWKS fetches and caches the JWKS from the configured URL
func (v *JWTValidator) refreshJWKS() error {
	if v.config.JWKSUrl == "" {
		return fmt.Errorf("JWKS URL not configured")
	}

	// Fetch JWKS from the URL
	resp, err := v.httpClient.Get(v.config.JWKSUrl)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: HTTP %d", resp.StatusCode)
	}

	// Parse the JWKS
	jwksSet, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Update the cache
	v.jwksMutex.Lock()
	v.jwksCache = jwksSet
	v.lastRefresh = time.Now()
	v.jwksMutex.Unlock()

	return nil
}

// mapClaimsToStruct converts jwt.MapClaims to our Claims struct
func (v *JWTValidator) mapClaimsToStruct(claims jwt.MapClaims) (*interfaces.Claims, error) {
	userClaims := &interfaces.Claims{}

	// Extract user ID
	if userID, ok := claims["user_id"].(string); ok {
		userClaims.UserID = userID
	} else if sub, ok := claims["sub"].(string); ok {
		userClaims.UserID = sub
		userClaims.Subject = sub
	}

	// Extract email
	if email, ok := claims["email"].(string); ok {
		userClaims.Email = email
	}

	// Extract roles
	if rolesInterface, ok := claims["roles"]; ok {
		if rolesList, ok := rolesInterface.([]interface{}); ok {
			roles := make([]string, len(rolesList))
			for i, role := range rolesList {
				if roleStr, ok := role.(string); ok {
					roles[i] = roleStr
				}
			}
			userClaims.Roles = roles
		}
	}

	// Extract permissions
	if permsInterface, ok := claims["permissions"]; ok {
		if permsList, ok := permsInterface.([]interface{}); ok {
			permissions := make([]string, len(permsList))
			for i, perm := range permsList {
				if permStr, ok := perm.(string); ok {
					permissions[i] = permStr
				}
			}
			userClaims.Permissions = permissions
		}
	}

	// Extract expiration time
	if exp, ok := claims["exp"].(float64); ok {
		userClaims.ExpiresAt = int64(exp)
	}

	// Extract issued at time
	if iat, ok := claims["iat"].(float64); ok {
		userClaims.IssuedAt = int64(iat)
	}

	// Extract issuer
	if iss, ok := claims["iss"].(string); ok {
		userClaims.Issuer = iss
	}

	// Extract subject if not already set
	if userClaims.Subject == "" {
		if sub, ok := claims["sub"].(string); ok {
			userClaims.Subject = sub
		}
	}

	// Validate required fields
	if userClaims.UserID == "" {
		return nil, fmt.Errorf("missing user_id in token claims")
	}

	if userClaims.ExpiresAt == 0 {
		return nil, fmt.Errorf("missing exp in token claims")
	}

	// Check if token is expired
	if time.Now().Unix() > userClaims.ExpiresAt {
		return nil, fmt.Errorf("token has expired")
	}

	return userClaims, nil
}