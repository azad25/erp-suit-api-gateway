package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// ElasticLogger implements the Logger interface for Elasticsearch
type ElasticLogger struct {
	config     *config.ElasticsearchConfig
	httpClient *http.Client
	buffer     chan LogEntry
	batchSize  int
	flushTimer *time.Timer
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	closed     bool
}

// LogEntry represents a generic log entry
type LogEntry struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// NewElasticLogger creates a new Elasticsearch logger
func NewElasticLogger(cfg *config.LoggingConfig) (*ElasticLogger, error) {
	if len(cfg.Elasticsearch.URLs) == 0 {
		return nil, fmt.Errorf("elasticsearch URLs cannot be empty")
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger := &ElasticLogger{
		config: &cfg.Elasticsearch,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		buffer:    make(chan LogEntry, cfg.BufferSize),
		batchSize: cfg.BufferSize / 10, // Process in smaller batches
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start the background processor
	logger.wg.Add(1)
	go logger.processLogs(cfg.FlushInterval)

	return logger, nil
}

// LogRequest logs a request entry
func (l *ElasticLogger) LogRequest(ctx context.Context, entry interfaces.RequestLogEntry) error {
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return fmt.Errorf("logger is closed")
	}
	l.mu.RUnlock()

	logEntry := LogEntry{
		Type: "request",
		Data: entry,
	}

	select {
	case l.buffer <- logEntry:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Buffer is full, log synchronously to prevent data loss
		return l.sendToElasticsearch([]LogEntry{logEntry})
	}
}

// LogError logs an error entry
func (l *ElasticLogger) LogError(ctx context.Context, entry interfaces.ErrorLogEntry) error {
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return fmt.Errorf("logger is closed")
	}
	l.mu.RUnlock()

	// Add stack trace if not provided
	if entry.StackTrace == "" {
		entry.StackTrace = l.getStackTrace()
	}

	logEntry := LogEntry{
		Type: "error",
		Data: entry,
	}

	select {
	case l.buffer <- logEntry:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Buffer is full, log synchronously for errors to prevent data loss
		return l.sendToElasticsearch([]LogEntry{logEntry})
	}
}

// LogEvent logs an event entry
func (l *ElasticLogger) LogEvent(ctx context.Context, entry interfaces.EventLogEntry) error {
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return fmt.Errorf("logger is closed")
	}
	l.mu.RUnlock()

	logEntry := LogEntry{
		Type: "event",
		Data: entry,
	}

	select {
	case l.buffer <- logEntry:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Buffer is full, drop event logs to prevent blocking
		return fmt.Errorf("log buffer full, event dropped")
	}
}

// LogMetric logs a metric entry
func (l *ElasticLogger) LogMetric(ctx context.Context, entry interfaces.MetricLogEntry) error {
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return fmt.Errorf("logger is closed")
	}
	l.mu.RUnlock()

	logEntry := LogEntry{
		Type: "metric",
		Data: entry,
	}

	select {
	case l.buffer <- logEntry:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Buffer is full, drop metric logs to prevent blocking
		return fmt.Errorf("log buffer full, metric dropped")
	}
}

// Close closes the logger and flushes remaining logs
func (l *ElasticLogger) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	// Cancel context to stop background processor
	l.cancel()

	// Close buffer channel
	close(l.buffer)

	// Wait for background processor to finish
	l.wg.Wait()

	return nil
}

// processLogs processes logs in batches
func (l *ElasticLogger) processLogs(flushInterval time.Duration) {
	defer l.wg.Done()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]LogEntry, 0, l.batchSize)

	for {
		select {
		case <-l.ctx.Done():
			// Flush remaining logs before exiting
			if len(batch) > 0 {
				l.sendToElasticsearch(batch)
			}
			return

		case <-ticker.C:
			// Flush batch on timer
			if len(batch) > 0 {
				l.sendToElasticsearch(batch)
				batch = batch[:0] // Reset batch
			}

		case entry, ok := <-l.buffer:
			if !ok {
				// Channel closed, flush remaining logs
				if len(batch) > 0 {
					l.sendToElasticsearch(batch)
				}
				return
			}

			batch = append(batch, entry)

			// Flush batch when it reaches the batch size
			if len(batch) >= l.batchSize {
				l.sendToElasticsearch(batch)
				batch = batch[:0] // Reset batch
			}
		}
	}
}

// sendToElasticsearch sends a batch of log entries to Elasticsearch
func (l *ElasticLogger) sendToElasticsearch(entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	// Build bulk request body
	var bulkBody bytes.Buffer
	for _, entry := range entries {
		// Index metadata
		indexMeta := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": l.getIndexName(entry),
			},
		}

		metaJSON, err := json.Marshal(indexMeta)
		if err != nil {
			continue // Skip this entry
		}

		bulkBody.Write(metaJSON)
		bulkBody.WriteByte('\n')

		// Document data
		docJSON, err := json.Marshal(entry.Data)
		if err != nil {
			continue // Skip this entry
		}

		bulkBody.Write(docJSON)
		bulkBody.WriteByte('\n')
	}

	// Send bulk request to Elasticsearch
	return l.sendBulkRequest(bulkBody.Bytes())
}

// sendBulkRequest sends a bulk request to Elasticsearch
func (l *ElasticLogger) sendBulkRequest(body []byte) error {
	// Try each Elasticsearch URL until one succeeds
	var lastErr error
	for _, url := range l.config.URLs {
		bulkURL := strings.TrimSuffix(url, "/") + "/_bulk"

		req, err := http.NewRequestWithContext(l.ctx, "POST", bulkURL, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/x-ndjson")

		// Add authentication if configured
		if l.config.Username != "" && l.config.Password != "" {
			req.SetBasicAuth(l.config.Username, l.config.Password)
		}

		resp, err := l.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Read and close response body
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Check for errors in the bulk response
			var bulkResp map[string]interface{}
			if err := json.Unmarshal(respBody, &bulkResp); err == nil {
				if errors, ok := bulkResp["errors"].(bool); ok && errors {
					// Log bulk errors but don't fail the entire batch
					fmt.Printf("Elasticsearch bulk request had errors: %s\n", string(respBody))
				}
			}
			return nil // Success
		}

		lastErr = fmt.Errorf("elasticsearch request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("all elasticsearch URLs failed, last error: %w", lastErr)
}

// getIndexName returns the index name for a log entry
func (l *ElasticLogger) getIndexName(entry LogEntry) string {
	// Use date-based index names for better management
	date := time.Now().Format("2006.01.02")
	return fmt.Sprintf("%s-%s-%s", l.config.IndexName, entry.Type, date)
}

// getStackTrace returns the current stack trace
func (l *ElasticLogger) getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:]) // Skip getStackTrace, LogError, and the caller
	frames := runtime.CallersFrames(pcs[:n])

	var stackTrace strings.Builder
	for {
		frame, more := frames.Next()
		if !more {
			break
		}

		stackTrace.WriteString(fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function))
	}

	return stackTrace.String()
}

// Health checks the health of the Elasticsearch connection
func (l *ElasticLogger) Health() error {
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return fmt.Errorf("logger is closed")
	}
	l.mu.RUnlock()

	// Try to connect to at least one Elasticsearch URL
	var lastErr error
	for _, url := range l.config.URLs {
		healthURL := strings.TrimSuffix(url, "/") + "/_cluster/health"

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}

		// Add authentication if configured
		if l.config.Username != "" && l.config.Password != "" {
			req.SetBasicAuth(l.config.Username, l.config.Password)
		}

		resp, err := l.httpClient.Do(req)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil // At least one URL is healthy
		}

		lastErr = fmt.Errorf("elasticsearch health check failed with status %d", resp.StatusCode)
	}

	return fmt.Errorf("all elasticsearch URLs are unhealthy, last error: %w", lastErr)
}

// GetBufferSize returns the current buffer size
func (l *ElasticLogger) GetBufferSize() int {
	return len(l.buffer)
}

// GetBufferCapacity returns the buffer capacity
func (l *ElasticLogger) GetBufferCapacity() int {
	return cap(l.buffer)
}