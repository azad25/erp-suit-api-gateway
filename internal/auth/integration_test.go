package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/middleware"
)

// TestJWTIntegration tests the complete JWT validation flow
func TestJWTIntegration(t *testing.T) {
	// Generate test keys
	privateKey, publicKey, err := generateRSAKeyPair()
	assert.NoError(t, err)

	keyID := "test-key-id"
	issuer := "test-issuer"

	// Create JWKS server
	jwksData, err := createTestJWKS(publicKey, keyID)
	assert.NoError(t, err)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksData))
	}))
	defer jwksServer.Close()

	// Create test configuration
	cfg := &config.JWTConfig{
		JWKSUrl:   jwksServer.URL,
		Algorithm: "RS256",
		Issuer:    issuer,
		CacheTTL:  time.Hour,
	}

	// Create JWT validator
	validator := NewJWTValidator(cfg, nil)

	// Create authentication middleware
	authMiddleware := middleware.NewAuthMiddleware(validator, nil)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Protected endpoint
	router.GET("/protected", authMiddleware.RequireAuth(), func(c *gin.Context) {
		userID, _ := middleware.GetUserID(c)
		roles, _ := middleware.GetUserRoles(c)
		permissions, _ := middleware.GetUserPermissions(c)

		c.JSON(http.StatusOK, gin.H{
			"message":     "success",
			"user_id":     userID,
			"roles":       roles,
			"permissions": permissions,
		})
	})

	// Optional auth endpoint
	router.GET("/optional", authMiddleware.OptionalJWT(), func(c *gin.Context) {
		if middleware.IsAuthenticated(c) {
			userID, _ := middleware.GetUserID(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "authenticated",
				"user_id": userID,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"message": "anonymous",
			})
		}
	})

	t.Run("ValidTokenAccess", func(t *testing.T) {
		// Create valid token
		claims := jwt.MapClaims{
			"user_id":     "test-user-123",
			"email":       "test@example.com",
			"roles":       []string{"user", "admin"},
			"permissions": []string{"read", "write", "delete"},
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iat":         time.Now().Unix(),
			"iss":         issuer,
			"sub":         "test-user-123",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test protected endpoint
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "success", response["message"])
		assert.Equal(t, "test-user-123", response["user_id"])
		assert.Equal(t, []interface{}{"user", "admin"}, response["roles"])
		assert.Equal(t, []interface{}{"read", "write", "delete"}, response["permissions"])
	})

	t.Run("UnauthorizedAccess", func(t *testing.T) {
		// Test protected endpoint without token
		req := httptest.NewRequest("GET", "/protected", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Authorization header is required", response["message"])
	})

	t.Run("OptionalAuthWithToken", func(t *testing.T) {
		// Create valid token
		claims := jwt.MapClaims{
			"user_id": "test-user-456",
			"email":   "test2@example.com",
			"exp":     time.Now().Add(time.Hour).Unix(),
			"iat":     time.Now().Unix(),
			"iss":     issuer,
			"sub":     "test-user-456",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test optional endpoint with token
		req := httptest.NewRequest("GET", "/optional", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "authenticated", response["message"])
		assert.Equal(t, "test-user-456", response["user_id"])
	})

	t.Run("OptionalAuthWithoutToken", func(t *testing.T) {
		// Test optional endpoint without token
		req := httptest.NewRequest("GET", "/optional", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "anonymous", response["message"])
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		// Create expired token
		claims := jwt.MapClaims{
			"user_id": "test-user-789",
			"email":   "test3@example.com",
			"exp":     time.Now().Add(-time.Hour).Unix(), // Expired
			"iat":     time.Now().Add(-2 * time.Hour).Unix(),
			"iss":     issuer,
			"sub":     "test-user-789",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test protected endpoint with expired token
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Invalid token", response["message"])
	})
}

// TestRoleBasedAccess tests role-based access control
func TestRoleBasedAccess(t *testing.T) {
	// Generate test keys
	privateKey, publicKey, err := generateRSAKeyPair()
	assert.NoError(t, err)

	keyID := "test-key-id"
	issuer := "test-issuer"

	// Create JWKS server
	jwksData, err := createTestJWKS(publicKey, keyID)
	assert.NoError(t, err)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksData))
	}))
	defer jwksServer.Close()

	// Create test configuration
	cfg := &config.JWTConfig{
		JWKSUrl:   jwksServer.URL,
		Algorithm: "RS256",
		Issuer:    issuer,
		CacheTTL:  time.Hour,
	}

	// Create JWT validator
	validator := NewJWTValidator(cfg, nil)

	// Create authentication middleware
	authMiddleware := middleware.NewAuthMiddleware(validator, nil)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Admin-only endpoint
	router.GET("/admin", authMiddleware.RequireAuth(), func(c *gin.Context) {
		if !middleware.HasRole(c, "admin") {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "Admin role required",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "admin access granted",
		})
	})

	// Permission-based endpoint
	router.GET("/write", authMiddleware.RequireAuth(), func(c *gin.Context) {
		if !middleware.HasPermission(c, "write") {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "Write permission required",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "write access granted",
		})
	})

	t.Run("AdminRoleAccess", func(t *testing.T) {
		// Create token with admin role
		claims := jwt.MapClaims{
			"user_id":     "admin-user",
			"email":       "admin@example.com",
			"roles":       []string{"user", "admin"},
			"permissions": []string{"read", "write", "delete"},
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iat":         time.Now().Unix(),
			"iss":         issuer,
			"sub":         "admin-user",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test admin endpoint
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "admin access granted", response["message"])
	})

	t.Run("NonAdminRoleAccess", func(t *testing.T) {
		// Create token without admin role
		claims := jwt.MapClaims{
			"user_id":     "regular-user",
			"email":       "user@example.com",
			"roles":       []string{"user"},
			"permissions": []string{"read"},
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iat":         time.Now().Unix(),
			"iss":         issuer,
			"sub":         "regular-user",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test admin endpoint
		req := httptest.NewRequest("GET", "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Admin role required", response["message"])
	})

	t.Run("WritePermissionAccess", func(t *testing.T) {
		// Create token with write permission
		claims := jwt.MapClaims{
			"user_id":     "writer-user",
			"email":       "writer@example.com",
			"roles":       []string{"user"},
			"permissions": []string{"read", "write"},
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iat":         time.Now().Unix(),
			"iss":         issuer,
			"sub":         "writer-user",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test write endpoint
		req := httptest.NewRequest("GET", "/write", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "write access granted", response["message"])
	})

	t.Run("NoWritePermissionAccess", func(t *testing.T) {
		// Create token without write permission
		claims := jwt.MapClaims{
			"user_id":     "reader-user",
			"email":       "reader@example.com",
			"roles":       []string{"user"},
			"permissions": []string{"read"},
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iat":         time.Now().Unix(),
			"iss":         issuer,
			"sub":         "reader-user",
		}

		tokenString, err := createTestToken(privateKey, keyID, claims)
		assert.NoError(t, err)

		// Test write endpoint
		req := httptest.NewRequest("GET", "/write", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, false, response["success"])
		assert.Equal(t, "Write permission required", response["message"])
	})
}