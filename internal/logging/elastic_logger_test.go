package logging

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

func TestNewElasticLogger(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.LoggingConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &config.LoggingConfig{
				BufferSize:    100,
				FlushInterval: 1 * time.Second,
				Elasticsearch: config.ElasticsearchConfig{
					URLs:      []string{"http://localhost:9200"},
					IndexName: "test-logs",
				},
			},
			wantErr: false,
		},
		{
			name: "empty URLs",
			config: &config.LoggingConfig{
				BufferSize:    100,
				FlushInterval: 1 * time.Second,
				Elasticsearch: config.ElasticsearchConfig{
					URLs:      []string{},
					IndexName: "test-logs",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewElasticLogger(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
				if logger != nil {
					logger.Close()
				}
			}
		})
	}
}

func TestElasticLogger_LogRequest(t *testing.T) {
	// Create a mock Elasticsearch server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/_bulk", r.URL.Path)
		assert.Equal(t, "application/x-ndjson", r.Header.Get("Content-Type"))

		// Return successful response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 100 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test logging a request
	entry := interfaces.RequestLogEntry{
		Timestamp:  time.Now(),
		RequestID:  "test-request-123",
		UserID:     "user-456",
		Method:     "GET",
		Path:       "/api/test",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
		RemoteIP:   "127.0.0.1",
	}

	ctx := context.Background()
	err = logger.LogRequest(ctx, entry)
	assert.NoError(t, err)

	// Wait for async processing
	time.Sleep(200 * time.Millisecond)
}

func TestElasticLogger_LogError(t *testing.T) {
	// Create a mock Elasticsearch server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/_bulk", r.URL.Path)

		// Return successful response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 100 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test logging an error
	entry := interfaces.ErrorLogEntry{
		Timestamp: time.Now(),
		RequestID: "test-request-123",
		UserID:    "user-456",
		Level:     interfaces.LogLevelError,
		Message:   "Test error message",
		Error:     "test error",
		Service:   "test-service",
		Component: "test-component",
	}

	ctx := context.Background()
	err = logger.LogError(ctx, entry)
	assert.NoError(t, err)

	// Wait for async processing
	time.Sleep(200 * time.Millisecond)
}

func TestElasticLogger_LogEvent(t *testing.T) {
	// Create a mock Elasticsearch server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 100 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test logging an event
	entry := interfaces.EventLogEntry{
		Timestamp:     time.Now(),
		EventID:       "event-123",
		EventType:     "user_login",
		UserID:        "user-456",
		CorrelationID: "corr-789",
		Source:        "test-service",
		Data:          map[string]interface{}{"key": "value"},
		Success:       true,
	}

	ctx := context.Background()
	err = logger.LogEvent(ctx, entry)
	assert.NoError(t, err)

	// Wait for async processing
	time.Sleep(200 * time.Millisecond)
}

func TestElasticLogger_LogMetric(t *testing.T) {
	// Create a mock Elasticsearch server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 100 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test logging a metric
	entry := interfaces.MetricLogEntry{
		Timestamp:  time.Now(),
		MetricName: "response_time",
		MetricType: "histogram",
		Value:      123.45,
		Labels:     map[string]string{"endpoint": "/api/test"},
		Unit:       "ms",
	}

	ctx := context.Background()
	err = logger.LogMetric(ctx, entry)
	assert.NoError(t, err)

	// Wait for async processing
	time.Sleep(200 * time.Millisecond)
}

func TestElasticLogger_BatchProcessing(t *testing.T) {
	requestCount := 0
	// Create a mock Elasticsearch server that counts requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    5, // Small buffer to trigger batching
		FlushInterval: 50 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Log multiple entries
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		entry := interfaces.RequestLogEntry{
			Timestamp: time.Now(),
			RequestID: "test-request-" + string(rune(i)),
			Method:    "GET",
			Path:      "/api/test",
		}
		err = logger.LogRequest(ctx, entry)
		assert.NoError(t, err)
	}

	// Wait for batch processing
	time.Sleep(200 * time.Millisecond)

	// Should have made at least 2 requests (due to batching)
	assert.GreaterOrEqual(t, requestCount, 2)
}

func TestElasticLogger_ErrorHandling(t *testing.T) {
	// Create a mock server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 50 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Log an entry (should not fail even if Elasticsearch returns error)
	entry := interfaces.RequestLogEntry{
		Timestamp: time.Now(),
		RequestID: "test-request-123",
		Method:    "GET",
		Path:      "/api/test",
	}

	ctx := context.Background()
	err = logger.LogRequest(ctx, entry)
	assert.NoError(t, err) // Should not fail immediately

	// Wait for processing
	time.Sleep(100 * time.Millisecond)
}

func TestElasticLogger_MultipleURLs(t *testing.T) {
	// Create two mock servers - first fails, second succeeds
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer successServer.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 50 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{failServer.URL, successServer.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Log an entry - should succeed using the second URL
	entry := interfaces.RequestLogEntry{
		Timestamp: time.Now(),
		RequestID: "test-request-123",
		Method:    "GET",
		Path:      "/api/test",
	}

	ctx := context.Background()
	err = logger.LogRequest(ctx, entry)
	assert.NoError(t, err)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)
}

func TestElasticLogger_Authentication(t *testing.T) {
	// Create a mock server that checks authentication
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "testuser" || password != "testpass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 50 * time.Millisecond,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			Username:  "testuser",
			Password:  "testpass",
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Log an entry - should succeed with authentication
	entry := interfaces.RequestLogEntry{
		Timestamp: time.Now(),
		RequestID: "test-request-123",
		Method:    "GET",
		Path:      "/api/test",
	}

	ctx := context.Background()
	err = logger.LogRequest(ctx, entry)
	assert.NoError(t, err)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)
}

func TestElasticLogger_Health(t *testing.T) {
	// Create a healthy mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_cluster/health") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"green"}`))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
		}
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test health check
	err = logger.Health()
	assert.NoError(t, err)
}

func TestElasticLogger_HealthUnhealthy(t *testing.T) {
	// Create an unhealthy mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{server.URL},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test health check - should fail
	err = logger.Health()
	assert.Error(t, err)
}

func TestElasticLogger_Close(t *testing.T) {
	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{"http://localhost:9200"},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)

	// Test closing
	err = logger.Close()
	assert.NoError(t, err)

	// Test logging after close - should fail
	entry := interfaces.RequestLogEntry{
		Timestamp: time.Now(),
		RequestID: "test-request-123",
	}

	ctx := context.Background()
	err = logger.LogRequest(ctx, entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger is closed")
}

func TestElasticLogger_BufferMetrics(t *testing.T) {
	config := &config.LoggingConfig{
		BufferSize:    100,
		FlushInterval: 1 * time.Second,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{"http://localhost:9200"},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test buffer metrics
	assert.Equal(t, 0, logger.GetBufferSize())
	assert.Equal(t, 100, logger.GetBufferCapacity())
}

func TestGetIndexName(t *testing.T) {
	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{"http://localhost:9200"},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test index name generation
	entry := LogEntry{Type: "request"}
	indexName := logger.getIndexName(entry)

	// Should include base name, type, and date
	assert.Contains(t, indexName, "test-logs")
	assert.Contains(t, indexName, "request")
	assert.Contains(t, indexName, time.Now().Format("2006.01.02"))
}

func TestGetStackTrace(t *testing.T) {
	config := &config.LoggingConfig{
		BufferSize:    10,
		FlushInterval: 1 * time.Second,
		Elasticsearch: config.ElasticsearchConfig{
			URLs:      []string{"http://localhost:9200"},
			IndexName: "test-logs",
		},
	}

	logger, err := NewElasticLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test stack trace generation
	stackTrace := logger.getStackTrace()
	assert.NotEmpty(t, stackTrace)
	// Just verify it contains some file path and line number
	assert.Contains(t, stackTrace, ".go:")
}