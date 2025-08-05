package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// KafkaLoggerIntegration integrates the existing ElasticLogger with Kafka
type KafkaLoggerIntegration struct {
	elasticLogger *ElasticLogger
	kafkaProducer sarama.AsyncProducer
	config        *config.KafkaConfig
	buffer        chan KafkaLogMessage
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	closed        bool
}

// KafkaLogMessage represents a log message for Kafka
type KafkaLogMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"@timestamp"`
	Service   string      `json:"service"`
	Data      interface{} `json:"data"`
}

// NewKafkaLoggerIntegration creates a new Kafka-integrated logger
func NewKafkaLoggerIntegration(cfg *config.LoggingConfig, kafkaConfig *config.KafkaConfig) (*KafkaLoggerIntegration, error) {
	// Create the base Elasticsearch logger
	elasticLogger, err := NewElasticLogger(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch logger: %w", err)
	}

	// Create Kafka producer if Kafka is configured
	var kafkaProducer sarama.AsyncProducer
	if kafkaConfig != nil && len(kafkaConfig.Brokers) > 0 {
		saramaConfig := sarama.NewConfig()
		saramaConfig.Producer.Return.Successes = false // We don't need success confirmations for logs
		saramaConfig.Producer.Return.Errors = true
		saramaConfig.Producer.RequiredAcks = sarama.WaitForLocal // Faster than WaitForAll for logs
		saramaConfig.Producer.Compression = sarama.CompressionSnappy
		saramaConfig.Producer.Flush.Messages = kafkaConfig.FlushMessages
		saramaConfig.Producer.Flush.Bytes = kafkaConfig.FlushBytes
		saramaConfig.Producer.Flush.Frequency = kafkaConfig.FlushTimeout
		saramaConfig.Producer.Retry.Max = kafkaConfig.RetryMax
		saramaConfig.Producer.Retry.Backoff = kafkaConfig.RetryBackoff

		producer, err := sarama.NewAsyncProducer(kafkaConfig.Brokers, saramaConfig)
		if err != nil {
			// Don't fail if Kafka is not available, just log to Elasticsearch
			fmt.Printf("Warning: Failed to create Kafka producer: %v\n", err)
		} else {
			kafkaProducer = producer
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	integration := &KafkaLoggerIntegration{
		elasticLogger: elasticLogger,
		kafkaProducer: kafkaProducer,
		config:        kafkaConfig,
		buffer:        make(chan KafkaLogMessage, 1000),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Start background Kafka processor if Kafka is available
	if kafkaProducer != nil {
		integration.wg.Add(2)
		go integration.processKafkaLogs()
		go integration.handleKafkaErrors()
	}

	return integration, nil
}

// LogRequest logs a request entry to both Elasticsearch and Kafka
func (k *KafkaLoggerIntegration) LogRequest(ctx context.Context, entry interfaces.RequestLogEntry) error {
	// Log to Elasticsearch
	if err := k.elasticLogger.LogRequest(ctx, entry); err != nil {
		// Don't fail if Elasticsearch is down, but log the error
		fmt.Printf("Warning: Failed to log to Elasticsearch: %v\n", err)
	}

	// Log to Kafka if available
	if k.kafkaProducer != nil {
		k.sendToKafka("request", entry)
	}

	return nil
}

// LogError logs an error entry to both Elasticsearch and Kafka
func (k *KafkaLoggerIntegration) LogError(ctx context.Context, entry interfaces.ErrorLogEntry) error {
	// Log to Elasticsearch
	if err := k.elasticLogger.LogError(ctx, entry); err != nil {
		fmt.Printf("Warning: Failed to log error to Elasticsearch: %v\n", err)
	}

	// Log to Kafka if available (high priority for errors)
	if k.kafkaProducer != nil {
		k.sendToKafka("error", entry)
	}

	return nil
}

// LogEvent logs an event entry to both Elasticsearch and Kafka
func (k *KafkaLoggerIntegration) LogEvent(ctx context.Context, entry interfaces.EventLogEntry) error {
	// Log to Elasticsearch
	if err := k.elasticLogger.LogEvent(ctx, entry); err != nil {
		fmt.Printf("Warning: Failed to log event to Elasticsearch: %v\n", err)
	}

	// Log to Kafka if available
	if k.kafkaProducer != nil {
		k.sendToKafka("event", entry)
	}

	return nil
}

// LogMetric logs a metric entry to both Elasticsearch and Kafka
func (k *KafkaLoggerIntegration) LogMetric(ctx context.Context, entry interfaces.MetricLogEntry) error {
	// Log to Elasticsearch
	if err := k.elasticLogger.LogMetric(ctx, entry); err != nil {
		fmt.Printf("Warning: Failed to log metric to Elasticsearch: %v\n", err)
	}

	// Log to Kafka if available
	if k.kafkaProducer != nil {
		k.sendToKafka("metric", entry)
	}

	return nil
}

// sendToKafka sends a log message to Kafka
func (k *KafkaLoggerIntegration) sendToKafka(logType string, data interface{}) {
	k.mu.RLock()
	if k.closed {
		k.mu.RUnlock()
		return
	}
	k.mu.RUnlock()

	message := KafkaLogMessage{
		Type:      logType,
		Timestamp: time.Now().UTC(),
		Service:   "erp-api-gateway",
		Data:      data,
	}

	select {
	case k.buffer <- message:
		// Message buffered successfully
	case <-k.ctx.Done():
		// Context cancelled
		return
	default:
		// Buffer is full, drop the message to prevent blocking
		fmt.Printf("Warning: Kafka log buffer is full, dropping %s message\n", logType)
	}
}

// processKafkaLogs processes logs and sends them to Kafka
func (k *KafkaLoggerIntegration) processKafkaLogs() {
	defer k.wg.Done()

	for {
		select {
		case <-k.ctx.Done():
			return
		case message, ok := <-k.buffer:
			if !ok {
				return
			}

			// Serialize message
			data, err := json.Marshal(message)
			if err != nil {
				fmt.Printf("Warning: Failed to marshal Kafka log message: %v\n", err)
				continue
			}

			// Determine topic based on log type
			topic := k.getTopicForLogType(message.Type)

			// Create Kafka message
			kafkaMessage := &sarama.ProducerMessage{
				Topic: topic,
				Key:   sarama.StringEncoder(fmt.Sprintf("%s-%s", message.Service, message.Type)),
				Value: sarama.ByteEncoder(data),
				Headers: []sarama.RecordHeader{
					{Key: []byte("log-type"), Value: []byte(message.Type)},
					{Key: []byte("service"), Value: []byte(message.Service)},
					{Key: []byte("timestamp"), Value: []byte(message.Timestamp.Format(time.RFC3339))},
				},
			}

			// Send to Kafka
			select {
			case k.kafkaProducer.Input() <- kafkaMessage:
				// Message sent successfully
			case <-k.ctx.Done():
				return
			}
		}
	}
}

// handleKafkaErrors handles Kafka producer errors
func (k *KafkaLoggerIntegration) handleKafkaErrors() {
	defer k.wg.Done()

	for {
		select {
		case <-k.ctx.Done():
			return
		case err := <-k.kafkaProducer.Errors():
			if err != nil {
				fmt.Printf("Kafka producer error: %v\n", err.Err)
				// Could implement retry logic here if needed
			}
		}
	}
}

// getTopicForLogType returns the appropriate Kafka topic for a log type
func (k *KafkaLoggerIntegration) getTopicForLogType(logType string) string {
	switch logType {
	case "request":
		return "request-logs"
	case "error":
		return "error-logs"
	case "event":
		return "event-logs"
	case "metric":
		return "metric-logs"
	default:
		return "application-logs"
	}
}

// Close closes the integrated logger
func (k *KafkaLoggerIntegration) Close() error {
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		return nil
	}
	k.closed = true
	k.mu.Unlock()

	// Cancel context
	k.cancel()

	// Close Kafka producer if available
	if k.kafkaProducer != nil {
		k.kafkaProducer.AsyncClose()
		k.wg.Wait()
	}

	// Close buffer
	close(k.buffer)

	// Close Elasticsearch logger
	return k.elasticLogger.Close()
}

// Health checks the health of both Elasticsearch and Kafka
func (k *KafkaLoggerIntegration) Health() error {
	// Check Elasticsearch health
	if err := k.elasticLogger.Health(); err != nil {
		return fmt.Errorf("elasticsearch health check failed: %w", err)
	}

	// Kafka health is implicit - if messages are being sent without errors, it's healthy
	// We could implement a more sophisticated health check if needed

	return nil
}

// GetStats returns statistics about the integrated logger
func (k *KafkaLoggerIntegration) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"elasticsearch": map[string]interface{}{
			"buffer_size":     k.elasticLogger.GetBufferSize(),
			"buffer_capacity": k.elasticLogger.GetBufferCapacity(),
		},
		"kafka": map[string]interface{}{
			"enabled":         k.kafkaProducer != nil,
			"buffer_size":     len(k.buffer),
			"buffer_capacity": cap(k.buffer),
		},
		"is_closed": k.closed,
	}

	return stats
}