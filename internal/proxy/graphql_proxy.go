package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// GraphQLProxy handles proxying GraphQL requests to the GraphQL Gateway
type GraphQLProxy struct {
	config     *config.GraphQLConfig
	httpClient *http.Client
	logger     interfaces.SimpleLogger
}

// NewGraphQLProxy creates a new GraphQL proxy
func NewGraphQLProxy(config *config.GraphQLConfig, logger interfaces.SimpleLogger) *GraphQLProxy {
	return &GraphQLProxy{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger,
	}
}

// ProxyRequest proxies a GraphQL request to the GraphQL Gateway
func (p *GraphQLProxy) ProxyRequest(c *gin.Context) {
	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		p.logger.LogError(c.Request.Context(), "Failed to read request body", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request body",
		})
		return
	}

	// Create the target URL
	targetURL := fmt.Sprintf("http://%s:%d%s", 
		p.config.GatewayHost, 
		p.config.GatewayPort, 
		p.config.Endpoint,
	)

	// Create the proxy request
	req, err := http.NewRequestWithContext(
		c.Request.Context(),
		c.Request.Method,
		targetURL,
		bytes.NewReader(body),
	)
	if err != nil {
		p.logger.LogError(c.Request.Context(), "Failed to create proxy request", map[string]interface{}{
			"error": err.Error(),
			"target_url": targetURL,
		})
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to create proxy request",
		})
		return
	}

	// Copy headers from original request
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Add authentication headers if user is authenticated
	if userID, exists := c.Get("user_id"); exists {
		req.Header.Set("X-User-ID", userID.(string))
	}
	if orgID, exists := c.Get("organization_id"); exists {
		req.Header.Set("X-Organization-ID", orgID.(string))
	}

	// Make the request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logger.LogError(c.Request.Context(), "GraphQL proxy request failed", map[string]interface{}{
			"error": err.Error(),
			"target_url": targetURL,
		})
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": "GraphQL service unavailable",
		})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// Copy response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.LogError(c.Request.Context(), "Failed to read GraphQL response", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": "Failed to read GraphQL response",
		})
		return
	}

	// Set status code and return response
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)

	p.logger.LogInfo(c.Request.Context(), "GraphQL request proxied successfully", map[string]interface{}{
		"target_url": targetURL,
		"status_code": resp.StatusCode,
		"response_size": len(responseBody),
	})
}

// ProxyPlayground serves the GraphQL Playground
func (p *GraphQLProxy) ProxyPlayground(c *gin.Context) {
	if !p.config.EnablePlayground {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "GraphQL Playground is disabled",
		})
		return
	}

	// Create the target URL for playground
	targetURL := fmt.Sprintf("http://%s:%d%s", 
		p.config.GatewayHost, 
		p.config.GatewayPort, 
		p.config.Endpoint,
	)

	// Create the proxy request
	req, err := http.NewRequestWithContext(
		c.Request.Context(),
		"GET",
		targetURL,
		nil,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to create playground request",
		})
		return
	}

	// Copy headers
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Make the request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": "GraphQL Playground unavailable",
		})
		return
	}
	defer resp.Body.Close()

	// Copy response
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	responseBody, _ := io.ReadAll(resp.Body)
	c.Status(resp.StatusCode)
	c.Writer.Write(responseBody)
}