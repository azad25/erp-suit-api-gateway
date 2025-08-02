package graphql

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
)

func TestGraphQLHandler_HealthQuery(t *testing.T) {
	// Create basic config
	cfg := &config.Config{
		Server: config.ServerConfig{
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"http://localhost:3000"},
			},
		},
	}
	
	logger := logging.NewNoOpLogger()
	
	// For this basic test, we'll use nil for services since health query doesn't need them
	handler := NewGraphQLHandler(cfg, logger, nil, nil, nil)
	
	// Create test server
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/graphql", handler.ServeHTTP())
	
	// Prepare GraphQL query
	query := map[string]interface{}{
		"query": "{ health }",
	}
	
	jsonData, _ := json.Marshal(query)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	data := response["data"].(map[string]interface{})
	assert.Equal(t, "OK", data["health"])
}

// Note: More comprehensive tests with mocks would be added here
// For now, we focus on basic functionality tests

func TestGraphQLHandler_PlaygroundHandler(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"http://localhost:3000"},
			},
		},
	}
	
	logger := logging.NewNoOpLogger()
	
	handler := NewGraphQLHandler(cfg, logger, nil, nil, nil)
	
	// Create test server
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/playground", handler.PlaygroundHandler())
	
	req := httptest.NewRequest("GET", "/playground", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "GraphQL Playground")
}