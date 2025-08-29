package rest

import (
    "net/http"
    "net/http/httputil"
    "net/url"

    "github.com/gin-gonic/gin"
)

// AIWSProxyHandler proxies WebSocket connections to the AI Copilot service
type AIWSProxyHandler struct {
    target *url.URL
    proxy  *httputil.ReverseProxy
}

// NewAIWSProxyHandler creates a new WebSocket reverse proxy handler
func NewAIWSProxyHandler(targetBase string) (*AIWSProxyHandler, error) {
    u, err := url.Parse(targetBase)
    if err != nil {
        return nil, err
    }

    proxy := httputil.NewSingleHostReverseProxy(u)

    // Customize the director to preserve path and query
    originalDirector := proxy.Director
    proxy.Director = func(req *http.Request) {
        originalDirector(req)
        // Preserve the path and query exactly as the incoming request
        // e.g., /ws/chat?token=...
        // The SingleHostReverseProxy already sets scheme/host to target.
        // We only ensure that Host header is set to the target host for WS Handshake.
        req.Host = u.Host
    }

    // Support WebSocket by not modifying the connection headers; Go's reverse proxy
    // handles Upgrade and Connection headers automatically since Go 1.12+.

    return &AIWSProxyHandler{
        target: u,
        proxy:  proxy,
    }, nil
}

// Proxy handles the WebSocket upgrade and proxies traffic to the AI service
func (h *AIWSProxyHandler) Proxy(c *gin.Context) {
    // Log the WebSocket proxy attempt
    c.Header("X-Proxy-Target", h.target.String())
    
    // Ensure we proxy to the same path (/ws/chat) and preserve query string.
    // The reverse proxy uses the incoming request URL Path/RawQuery.
    h.proxy.ServeHTTP(c.Writer, c.Request)
}
