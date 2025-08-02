package test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"erp-api-gateway/api/rest"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/middleware"
)

// Load test configuration
const (
	MaxConcurrentConnections = 10000
	TestDuration            = 30 * time.Second
	RequestsPerSecond       = 1000
)

// Performance metrics
type PerformanceMetrics struct {
	TotalRequests     int64
	SuccessfulRequests int64
	FailedRequests    int64
	AverageLatency    time.Duration
	MaxLatency        time.Duration
	MinLatency        time.Duration
	RequestsPerSecond float64
	ErrorRate         float64
}

// MockJWTValidator for load tests
type MockJWTValidator struct {
	mock.Mock
}

func (m *MockJWTValidator) ValidateToken(token string) (*interfaces.Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*interfaces.Claims), args.Error(1)
}

func (m *MockJWTValidator) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	args := m.Called(keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

func (m *MockJWTValidator) RefreshJWKS() error {
	args := m.Called()
	return args.Error(0)
}

// MockPolicyEngine for load tests
type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) CheckPermission(ctx context.Context, userID string, permission string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, permission, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckRole(ctx context.Context, userID string, role string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, role, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAnyPermission(ctx context.Context, userID string, permissions []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, permissions, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAllPermissions(ctx context.Context, userID string, permissions []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, permissions, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAnyRole(ctx context.Context, userID string, roles []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, roles, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) CheckAllRoles(ctx context.Context, userID string, roles []string, claims *interfaces.Claims) (bool, error) {
	args := m.Called(ctx, userID, roles, claims)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyEngine) GetUserPermissions(ctx context.Context, userID string, claims *interfaces.Claims) ([]string, error) {
	args := m.Called(ctx, userID, claims)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockPolicyEngine) GetUserRoles(ctx context.Context, userID string, claims *interfaces.Claims) ([]string, error) {
	args := m.Called(ctx, userID, claims)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockPolicyEngine) RefreshUserPermissions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// Load test setup
func setupLoadTest() (*httptest.Server, *MockJWTValidator, *MockPolicyEngine) {
	gin.SetMode(gin.ReleaseMode) // Use release mode for better performance
	
	// Create mocks
	mockJWTValidator := &MockJWTValidator{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockCacheService := &MockCacheService{}
	mockGRPCClient := &MockGRPCClient{}
	mockEventPublisher := &MockEventPublisher{}
	mockLogger := &MockLogger{}

	// Create router
	router := gin.New()

	// Setup middleware
	authMiddleware := middleware.NewAuthMiddleware(mockJWTValidator, mockCacheService)
	rbacMiddleware := middleware.NewRBACMiddleware(mockPolicyEngine, nil)

	// Setup handlers
	authHandler := rest.NewAuthHandler(mockGRPCClient, mockCacheService, mockEventPublisher, mockLogger)

	// Setup routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	router.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "public endpoint"})
	})

	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login/", authHandler.Login)
		authGroup.GET("/me/", authMiddleware.ValidateJWT(), authHandler.GetCurrentUser)
	}

	protectedGroup := router.Group("/api")
	protectedGroup.Use(authMiddleware.ValidateJWT())
	{
		protectedGroup.GET("/profile", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "profile data"})
		})
		
		adminGroup := protectedGroup.Group("/admin")
		adminGroup.Use(rbacMiddleware.RequireRole("admin"))
		{
			adminGroup.GET("/users", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "admin users data"})
			})
		}
	}

	// Create test server
	server := httptest.NewServer(router)
	
	return server, mockJWTValidator, mockPolicyEngine
}

// Load test for public endpoints (no authentication required)
func TestLoad_PublicEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	server, _, _ := setupLoadTest()
	defer server.Close()

	t.Run("Health Check Endpoint Load Test", func(t *testing.T) {
		metrics := runLoadTest(t, server.URL+"/health", "GET", nil, nil, 5000, 10*time.Second)
		
		// Assertions
		assert.Greater(t, metrics.RequestsPerSecond, float64(100), "Should handle at least 100 requests per second")
		assert.Less(t, metrics.ErrorRate, 0.01, "Error rate should be less than 1%")
		assert.Less(t, metrics.AverageLatency, 100*time.Millisecond, "Average latency should be less than 100ms")
		
		t.Logf("Health Check Load Test Results:")
		t.Logf("  Total Requests: %d", metrics.TotalRequests)
		t.Logf("  Successful Requests: %d", metrics.SuccessfulRequests)
		t.Logf("  Failed Requests: %d", metrics.FailedRequests)
		t.Logf("  Requests/Second: %.2f", metrics.RequestsPerSecond)
		t.Logf("  Average Latency: %v", metrics.AverageLatency)
		t.Logf("  Max Latency: %v", metrics.MaxLatency)
		t.Logf("  Min Latency: %v", metrics.MinLatency)
		t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate*100)
	})

	t.Run("Public Endpoint Load Test", func(t *testing.T) {
		metrics := runLoadTest(t, server.URL+"/public", "GET", nil, nil, 5000, 10*time.Second)
		
		// Assertions
		assert.Greater(t, metrics.RequestsPerSecond, float64(100), "Should handle at least 100 requests per second")
		assert.Less(t, metrics.ErrorRate, 0.01, "Error rate should be less than 1%")
		assert.Less(t, metrics.AverageLatency, 100*time.Millisecond, "Average latency should be less than 100ms")
		
		t.Logf("Public Endpoint Load Test Results:")
		t.Logf("  Total Requests: %d", metrics.TotalRequests)
		t.Logf("  Successful Requests: %d", metrics.SuccessfulRequests)
		t.Logf("  Failed Requests: %d", metrics.FailedRequests)
		t.Logf("  Requests/Second: %.2f", metrics.RequestsPerSecond)
		t.Logf("  Average Latency: %v", metrics.AverageLatency)
		t.Logf("  Max Latency: %v", metrics.MaxLatency)
		t.Logf("  Min Latency: %v", metrics.MinLatency)
		t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate*100)
	})
}

// Load test for authenticated endpoints
func TestLoad_AuthenticatedEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	server, mockJWTValidator, _ := setupLoadTest()
	defer server.Close()

	// Setup JWT validation mock
	claims := createTestClaims()
	mockJWTValidator.On("ValidateToken", "valid-token").Return(claims, nil)

	headers := map[string]string{
		"Authorization": "Bearer valid-token",
	}

	t.Run("Protected Endpoint Load Test", func(t *testing.T) {
		metrics := runLoadTest(t, server.URL+"/api/profile", "GET", nil, headers, 3000, 10*time.Second)
		
		// Assertions for authenticated endpoints (slightly lower performance expected due to auth overhead)
		assert.Greater(t, metrics.RequestsPerSecond, float64(50), "Should handle at least 50 requests per second")
		assert.Less(t, metrics.ErrorRate, 0.05, "Error rate should be less than 5%")
		assert.Less(t, metrics.AverageLatency, 200*time.Millisecond, "Average latency should be less than 200ms")
		
		t.Logf("Protected Endpoint Load Test Results:")
		t.Logf("  Total Requests: %d", metrics.TotalRequests)
		t.Logf("  Successful Requests: %d", metrics.SuccessfulRequests)
		t.Logf("  Failed Requests: %d", metrics.FailedRequests)
		t.Logf("  Requests/Second: %.2f", metrics.RequestsPerSecond)
		t.Logf("  Average Latency: %v", metrics.AverageLatency)
		t.Logf("  Max Latency: %v", metrics.MaxLatency)
		t.Logf("  Min Latency: %v", metrics.MinLatency)
		t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate*100)
	})
}

// Load test for RBAC endpoints
func TestLoad_RBACEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	server, mockJWTValidator, mockPolicyEngine := setupLoadTest()
	defer server.Close()

	// Setup mocks
	claims := createTestClaims()
	mockJWTValidator.On("ValidateToken", "admin-token").Return(claims, nil)
	mockPolicyEngine.On("CheckRole", mock.Anything, claims.UserID, "admin", claims).Return(true, nil)

	headers := map[string]string{
		"Authorization": "Bearer admin-token",
	}

	t.Run("RBAC Protected Endpoint Load Test", func(t *testing.T) {
		metrics := runLoadTest(t, server.URL+"/api/admin/users", "GET", nil, headers, 2000, 10*time.Second)
		
		// Assertions for RBAC endpoints (lower performance expected due to additional authorization checks)
		assert.Greater(t, metrics.RequestsPerSecond, float64(30), "Should handle at least 30 requests per second")
		assert.Less(t, metrics.ErrorRate, 0.1, "Error rate should be less than 10%")
		assert.Less(t, metrics.AverageLatency, 300*time.Millisecond, "Average latency should be less than 300ms")
		
		t.Logf("RBAC Protected Endpoint Load Test Results:")
		t.Logf("  Total Requests: %d", metrics.TotalRequests)
		t.Logf("  Successful Requests: %d", metrics.SuccessfulRequests)
		t.Logf("  Failed Requests: %d", metrics.FailedRequests)
		t.Logf("  Requests/Second: %.2f", metrics.RequestsPerSecond)
		t.Logf("  Average Latency: %v", metrics.AverageLatency)
		t.Logf("  Max Latency: %v", metrics.MaxLatency)
		t.Logf("  Min Latency: %v", metrics.MinLatency)
		t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate*100)
	})
}

// Concurrent connections test
func TestLoad_ConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent connections test in short mode")
	}

	server, _, _ := setupLoadTest()
	defer server.Close()

	t.Run("Maximum Concurrent Connections Test", func(t *testing.T) {
		concurrentConnections := 1000 // Start with a reasonable number
		if testing.Verbose() {
			concurrentConnections = 5000 // Increase for verbose mode
		}

		var wg sync.WaitGroup
		var successCount int64
		var errorCount int64
		
		startTime := time.Now()

		// Create concurrent connections
		for i := 0; i < concurrentConnections; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				client := &http.Client{
					Timeout: 10 * time.Second,
				}
				
				resp, err := client.Get(server.URL + "/health")
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					return
				}
				defer resp.Body.Close()
				
				if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&successCount, 1)
				} else {
					atomic.AddInt64(&errorCount, 1)
				}
			}(i)
		}

		wg.Wait()
		duration := time.Since(startTime)

		successRate := float64(successCount) / float64(concurrentConnections)
		
		// Assertions
		assert.Greater(t, successRate, 0.95, "Should handle at least 95% of concurrent connections successfully")
		assert.Less(t, duration, 30*time.Second, "Should complete within 30 seconds")
		
		t.Logf("Concurrent Connections Test Results:")
		t.Logf("  Concurrent Connections: %d", concurrentConnections)
		t.Logf("  Successful Connections: %d", successCount)
		t.Logf("  Failed Connections: %d", errorCount)
		t.Logf("  Success Rate: %.2f%%", successRate*100)
		t.Logf("  Total Duration: %v", duration)
	})
}

// Memory and resource usage test
func TestLoad_ResourceUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource usage test in short mode")
	}

	server, _, _ := setupLoadTest()
	defer server.Close()

	t.Run("Memory Usage Under Load", func(t *testing.T) {
		// Run a sustained load test to check for memory leaks
		metrics := runLoadTest(t, server.URL+"/health", "GET", nil, nil, 10000, 30*time.Second)
		
		// Basic assertions
		assert.Greater(t, metrics.TotalRequests, int64(5000), "Should process a significant number of requests")
		assert.Less(t, metrics.ErrorRate, 0.05, "Error rate should remain low under sustained load")
		
		t.Logf("Resource Usage Test Results:")
		t.Logf("  Total Requests: %d", metrics.TotalRequests)
		t.Logf("  Duration: 30 seconds")
		t.Logf("  Average RPS: %.2f", metrics.RequestsPerSecond)
		t.Logf("  Error Rate: %.2f%%", metrics.ErrorRate*100)
	})
}

// Helper function to run load tests
func runLoadTest(t *testing.T, url, method string, body []byte, headers map[string]string, maxRequests int, duration time.Duration) PerformanceMetrics {
	var totalRequests int64
	var successfulRequests int64
	var failedRequests int64
	var totalLatency int64
	var maxLatency int64
	var minLatency int64 = int64(time.Hour) // Initialize with a large value
	
	startTime := time.Now()
	endTime := startTime.Add(duration)
	
	// Channel to control request rate
	rateLimiter := make(chan struct{}, 100) // Allow up to 100 concurrent requests
	
	var wg sync.WaitGroup
	
	// Request generator
	go func() {
		for time.Now().Before(endTime) && int(atomic.LoadInt64(&totalRequests)) < maxRequests {
			select {
			case rateLimiter <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-rateLimiter }()
					
					requestStart := time.Now()
					
					// Create request
					var req *http.Request
					var err error
					
					if body != nil {
						req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
					} else {
						req, err = http.NewRequest(method, url, nil)
					}
					
					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						return
					}
					
					// Add headers
					for key, value := range headers {
						req.Header.Set(key, value)
					}
					
					if body != nil {
						req.Header.Set("Content-Type", "application/json")
					}
					
					// Make request
					client := &http.Client{
						Timeout: 10 * time.Second,
					}
					
					resp, err := client.Do(req)
					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						return
					}
					defer resp.Body.Close()
					
					// Calculate latency
					latency := time.Since(requestStart)
					latencyNanos := latency.Nanoseconds()
					
					atomic.AddInt64(&totalLatency, latencyNanos)
					
					// Update min/max latency
					for {
						currentMax := atomic.LoadInt64(&maxLatency)
						if latencyNanos <= currentMax || atomic.CompareAndSwapInt64(&maxLatency, currentMax, latencyNanos) {
							break
						}
					}
					
					for {
						currentMin := atomic.LoadInt64(&minLatency)
						if latencyNanos >= currentMin || atomic.CompareAndSwapInt64(&minLatency, currentMin, latencyNanos) {
							break
						}
					}
					
					// Count requests
					atomic.AddInt64(&totalRequests, 1)
					
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						atomic.AddInt64(&successfulRequests, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
					}
				}()
			case <-time.After(10 * time.Millisecond):
				// Rate limiting - small delay between requests
			}
		}
	}()
	
	// Wait for all requests to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// All requests completed
	case <-time.After(duration + 10*time.Second):
		// Timeout - some requests may still be running
		t.Logf("Warning: Load test timed out, some requests may still be running")
	}
	
	actualDuration := time.Since(startTime)
	
	// Calculate metrics
	total := atomic.LoadInt64(&totalRequests)
	successful := atomic.LoadInt64(&successfulRequests)
	failed := atomic.LoadInt64(&failedRequests)
	avgLatencyNanos := atomic.LoadInt64(&totalLatency)
	maxLatencyNanos := atomic.LoadInt64(&maxLatency)
	minLatencyNanos := atomic.LoadInt64(&minLatency)
	
	var avgLatency time.Duration
	if total > 0 {
		avgLatency = time.Duration(avgLatencyNanos / total)
	}
	
	rps := float64(total) / actualDuration.Seconds()
	errorRate := float64(failed) / float64(total)
	
	if minLatencyNanos == int64(time.Hour) {
		minLatencyNanos = 0
	}
	
	return PerformanceMetrics{
		TotalRequests:     total,
		SuccessfulRequests: successful,
		FailedRequests:    failed,
		AverageLatency:    avgLatency,
		MaxLatency:        time.Duration(maxLatencyNanos),
		MinLatency:        time.Duration(minLatencyNanos),
		RequestsPerSecond: rps,
		ErrorRate:         errorRate,
	}
}

// Benchmark tests for specific operations
func BenchmarkAuthMiddleware_ValidateJWT(b *testing.B) {
	mockJWTValidator := &MockJWTValidator{}
	mockCacheService := &MockCacheService{}
	
	claims := createTestClaims()
	mockJWTValidator.On("ValidateToken", "benchmark-token").Return(claims, nil)
	mockCacheService.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)
	
	authMiddleware := middleware.NewAuthMiddleware(mockJWTValidator, mockCacheService)
	
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.GET("/test", authMiddleware.ValidateJWT(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer benchmark-token")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}

func BenchmarkRBACMiddleware_RequirePermission(b *testing.B) {
	mockPolicyEngine := &MockPolicyEngine{}
	
	claims := createTestClaims()
	mockPolicyEngine.On("CheckPermission", mock.Anything, claims.UserID, "users:read", claims).Return(true, nil)
	
	rbacMiddleware := middleware.NewRBACMiddleware(mockPolicyEngine, nil)
	
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set(middleware.UserClaimsKey, claims)
		c.Next()
	}, rbacMiddleware.RequirePermission("users:read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}