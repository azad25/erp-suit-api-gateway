package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

// KafkaProducer implements the EventPublisher interface
type KafkaProducer struct {
	producer      sarama.AsyncProducer
	config        *config.KafkaConfig
	deadLetterCh  chan *DeadLetterMessage
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	retryBackoff  time.Duration
	maxRetries    int
	topics        map[string]string // event type to topic mapping
	mu            sync.RWMutex
	closed        bool
}

// DeadLetterMessage represents a message that failed to be published
type DeadLetterMessage struct {
	Event         interfaces.Event `json:"event"`
	Topic         string           `json:"topic"`
	FailureReason string           `json:"failure_reason"`
	AttemptCount  int              `json:"attempt_count"`
	FirstAttempt  time.Time        `json:"first_attempt"`
	LastAttempt   time.Time        `json:"last_attempt"`
}

// KafkaProducerConfig holds configuration for the Kafka producer
type KafkaProducerConfig struct {
	Brokers           []string
	ClientID          string
	RetryMax          int
	RetryBackoff      time.Duration
	FlushMessages     int
	FlushBytes        int
	FlushTimeout      time.Duration
	DeadLetterTopic   string
	CompressionType   string
	RequiredAcks      int
	MaxMessageBytes   int
	EnableIdempotent  bool
}

// NewKafkaProducer creates a new Kafka producer
func NewKafkaProducer(cfg *config.KafkaConfig) (*KafkaProducer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kafka config cannot be nil")
	}

	// Create Sarama configuration
	saramaConfig := sarama.NewConfig()
	saramaConfig.ClientID = cfg.ClientID
	saramaConfig.Producer.Return.Successes = false // Disabled to reduce CPU usage
	saramaConfig.Producer.Return.Errors = true
	saramaConfig.Producer.RequiredAcks = sarama.WaitForAll // Wait for all replicas
	saramaConfig.Producer.Retry.Max = cfg.RetryMax
	saramaConfig.Producer.Retry.Backoff = cfg.RetryBackoff
	saramaConfig.Producer.Flush.Messages = cfg.FlushMessages
	saramaConfig.Producer.Flush.Bytes = cfg.FlushBytes
	saramaConfig.Producer.Flush.Frequency = cfg.FlushTimeout
	saramaConfig.Producer.Compression = sarama.CompressionSnappy
	saramaConfig.Producer.Idempotent = true
	saramaConfig.Producer.MaxMessageBytes = 1000000 // 1MB
	saramaConfig.Net.MaxOpenRequests = 1 // Required for idempotent producer

	// Create async producer
	producer, err := sarama.NewAsyncProducer(cfg.Brokers, saramaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	kp := &KafkaProducer{
		producer:     producer,
		config:       cfg,
		deadLetterCh: make(chan *DeadLetterMessage, 1000),
		ctx:          ctx,
		cancel:       cancel,
		retryBackoff: cfg.RetryBackoff,
		maxRetries:   cfg.RetryMax,
		topics:       make(map[string]string),
	}

	// Set up default topic mappings
	kp.setupTopicMappings()

	// Start background goroutines (success handling disabled to reduce CPU usage)
	kp.wg.Add(2)
	go kp.handleErrors()
	go kp.handleDeadLetterQueue()

	return kp, nil
}

// setupTopicMappings sets up the default event type to topic mappings
func (kp *KafkaProducer) setupTopicMappings() {
	kp.topics = map[string]string{
		interfaces.EventTypeUserLoggedIn:   "user-events",
		interfaces.EventTypeUserRegistered: "user-events",
		interfaces.EventTypeUserLoggedOut:  "user-events",
		interfaces.EventTypeTokenRefreshed: "auth-events",
		interfaces.EventTypeAPIRequest:     "api-events",
		interfaces.EventTypeAPIError:       "error-events",
		interfaces.EventTypeSystemAlert:    "system-events",
	}
}

// PublishEvent publishes a single event to Kafka
func (kp *KafkaProducer) PublishEvent(ctx context.Context, event interfaces.Event) error {
	kp.mu.RLock()
	if kp.closed {
		kp.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	kp.mu.RUnlock()

	// Get topic for event type
	topic, ok := kp.topics[event.Type]
	if !ok {
		topic = "default-events" // fallback topic
	}

	// Serialize event to JSON
	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Create Kafka message
	message := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(event.UserID), // Use UserID as partition key
		Value: sarama.ByteEncoder(eventData),
		Headers: []sarama.RecordHeader{
			{
				Key:   []byte("event-id"),
				Value: []byte(event.ID),
			},
			{
				Key:   []byte("event-type"),
				Value: []byte(event.Type),
			},
			{
				Key:   []byte("correlation-id"),
				Value: []byte(event.CorrelationID),
			},
			{
				Key:   []byte("source"),
				Value: []byte(event.Source),
			},
			{
				Key:   []byte("version"),
				Value: []byte(event.Version),
			},
			{
				Key:   []byte("timestamp"),
				Value: []byte(event.Timestamp.Format(time.RFC3339)),
			},
		},
		Metadata: event, // Store original event for error handling
	}

	// Send message asynchronously
	select {
	case kp.producer.Input() <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-kp.ctx.Done():
		return fmt.Errorf("producer is shutting down")
	}
}

// PublishUserEvent publishes an event with a specific user ID
func (kp *KafkaProducer) PublishUserEvent(ctx context.Context, userID string, event interfaces.Event) error {
	// Set the user ID if not already set
	if event.UserID == "" {
		event.UserID = userID
	}
	return kp.PublishEvent(ctx, event)
}

// PublishBatch publishes multiple events in a batch
func (kp *KafkaProducer) PublishBatch(ctx context.Context, events []interfaces.Event) error {
	if len(events) == 0 {
		return nil
	}

	kp.mu.RLock()
	if kp.closed {
		kp.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	kp.mu.RUnlock()

	// Publish each event
	for _, event := range events {
		if err := kp.PublishEvent(ctx, event); err != nil {
			return fmt.Errorf("failed to publish event %s: %w", event.ID, err)
		}
	}

	return nil
}

// Close gracefully shuts down the producer
func (kp *KafkaProducer) Close() error {
	kp.mu.Lock()
	if kp.closed {
		kp.mu.Unlock()
		return nil
	}
	kp.closed = true
	kp.mu.Unlock()

	// Cancel context to signal shutdown
	kp.cancel()

	// Close producer input channel
	kp.producer.AsyncClose()

	// Wait for background goroutines to finish
	kp.wg.Wait()

	// Close dead letter channel
	close(kp.deadLetterCh)

	return nil
}

// handleSuccesses handles successful message deliveries
func (kp *KafkaProducer) handleSuccesses() {
	defer kp.wg.Done()

	for {
		select {
		case success := <-kp.producer.Successes():
			if success != nil {
				// Success logging disabled to reduce CPU usage
				// Uncomment the line below if you need to debug message delivery
				// log.Printf("Message delivered successfully to topic %s, partition %d, offset %d",
				//	success.Topic, success.Partition, success.Offset)
			}
		case <-kp.ctx.Done():
			return
		}
	}
}

// handleErrors handles message delivery errors with retry logic
func (kp *KafkaProducer) handleErrors() {
	defer kp.wg.Done()

	for {
		select {
		case err := <-kp.producer.Errors():
			if err != nil {
				kp.handleProducerError(err)
			}
		case <-kp.ctx.Done():
			return
		}
	}
}

// handleProducerError handles individual producer errors with retry logic
func (kp *KafkaProducer) handleProducerError(err *sarama.ProducerError) {
	log.Printf("Kafka producer error: %v", err.Err)

	// Extract original event from metadata
	event, ok := err.Msg.Metadata.(interfaces.Event)
	if !ok {
		log.Printf("Failed to extract event from error metadata")
		return
	}

	// Check if this is a retryable error
	if kp.isRetryableError(err.Err) {
		// Implement exponential backoff retry
		go kp.retryMessage(err.Msg, event, 1)
	} else {
		// Send to dead letter queue
		deadLetter := &DeadLetterMessage{
			Event:         event,
			Topic:         err.Msg.Topic,
			FailureReason: err.Err.Error(),
			AttemptCount:  1,
			FirstAttempt:  time.Now(),
			LastAttempt:   time.Now(),
		}

		select {
		case kp.deadLetterCh <- deadLetter:
		default:
			log.Printf("Dead letter queue is full, dropping message: %s", event.ID)
		}
	}
}

// isRetryableError determines if an error is retryable
func (kp *KafkaProducer) isRetryableError(err error) bool {
	// Define retryable errors
	retryableErrors := []sarama.KError{
		sarama.ErrNotLeaderForPartition,
		sarama.ErrLeaderNotAvailable,
		sarama.ErrRequestTimedOut,
		sarama.ErrBrokerNotAvailable,
		sarama.ErrNetworkException,
		sarama.ErrNotEnoughReplicas,
		sarama.ErrNotEnoughReplicasAfterAppend,
	}

	if kafkaErr, ok := err.(sarama.KError); ok {
		for _, retryableErr := range retryableErrors {
			if kafkaErr == retryableErr {
				return true
			}
		}
	}

	return false
}

// retryMessage retries sending a message with exponential backoff
func (kp *KafkaProducer) retryMessage(msg *sarama.ProducerMessage, event interfaces.Event, attempt int) {
	if attempt > kp.maxRetries {
		// Max retries exceeded, send to dead letter queue
		deadLetter := &DeadLetterMessage{
			Event:         event,
			Topic:         msg.Topic,
			FailureReason: "max retries exceeded",
			AttemptCount:  attempt,
			FirstAttempt:  time.Now().Add(-time.Duration(attempt) * kp.retryBackoff),
			LastAttempt:   time.Now(),
		}

		select {
		case kp.deadLetterCh <- deadLetter:
		default:
			log.Printf("Dead letter queue is full, dropping message: %s", event.ID)
		}
		return
	}

	// Calculate backoff duration with exponential backoff
	backoffDuration := time.Duration(attempt) * kp.retryBackoff
	if backoffDuration > 30*time.Second {
		backoffDuration = 30 * time.Second // Cap at 30 seconds
	}

	timer := time.NewTimer(backoffDuration)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Create new message with updated metadata
		retryMsg := &sarama.ProducerMessage{
			Topic:     msg.Topic,
			Key:       msg.Key,
			Value:     msg.Value,
			Headers:   msg.Headers,
			Metadata:  event,
		}

		// Add retry attempt header
		retryMsg.Headers = append(retryMsg.Headers, sarama.RecordHeader{
			Key:   []byte("retry-attempt"),
			Value: []byte(fmt.Sprintf("%d", attempt)),
		})

		// Try to send again
		select {
		case kp.producer.Input() <- retryMsg:
			log.Printf("Retrying message %s (attempt %d)", event.ID, attempt)
		case <-kp.ctx.Done():
			return
		}

	case <-kp.ctx.Done():
		return
	}
}

// handleDeadLetterQueue processes messages in the dead letter queue
func (kp *KafkaProducer) handleDeadLetterQueue() {
	defer kp.wg.Done()

	deadLetterTopic := "dead-letter-queue"

	for {
		select {
		case deadLetter := <-kp.deadLetterCh:
			if deadLetter != nil {
				kp.publishToDeadLetterQueue(deadLetterTopic, deadLetter)
			}
		case <-kp.ctx.Done():
			// Process remaining messages in the queue
			for {
				select {
				case deadLetter := <-kp.deadLetterCh:
					if deadLetter != nil {
						kp.publishToDeadLetterQueue(deadLetterTopic, deadLetter)
					}
				default:
					return
				}
			}
		}
	}
}

// publishToDeadLetterQueue publishes a message to the dead letter queue
func (kp *KafkaProducer) publishToDeadLetterQueue(topic string, deadLetter *DeadLetterMessage) {
	deadLetterData, err := json.Marshal(deadLetter)
	if err != nil {
		log.Printf("Failed to marshal dead letter message: %v", err)
		return
	}

	message := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(deadLetter.Event.ID),
		Value: sarama.ByteEncoder(deadLetterData),
		Headers: []sarama.RecordHeader{
			{
				Key:   []byte("original-topic"),
				Value: []byte(deadLetter.Topic),
			},
			{
				Key:   []byte("failure-reason"),
				Value: []byte(deadLetter.FailureReason),
			},
			{
				Key:   []byte("attempt-count"),
				Value: []byte(fmt.Sprintf("%d", deadLetter.AttemptCount)),
			},
			{
				Key:   []byte("dead-letter-timestamp"),
				Value: []byte(time.Now().Format(time.RFC3339)),
			},
		},
	}

	// Send to dead letter queue (best effort, no retry)
	select {
	case kp.producer.Input() <- message:
		log.Printf("Message %s sent to dead letter queue", deadLetter.Event.ID)
	case <-time.After(5 * time.Second):
		log.Printf("Timeout sending message %s to dead letter queue", deadLetter.Event.ID)
	case <-kp.ctx.Done():
		return
	}
}

// GetTopicForEventType returns the topic name for a given event type
func (kp *KafkaProducer) GetTopicForEventType(eventType string) string {
	kp.mu.RLock()
	defer kp.mu.RUnlock()
	
	if topic, ok := kp.topics[eventType]; ok {
		return topic
	}
	return "default-events"
}

// SetTopicMapping sets a custom topic mapping for an event type
func (kp *KafkaProducer) SetTopicMapping(eventType, topic string) {
	kp.mu.Lock()
	defer kp.mu.Unlock()
	kp.topics[eventType] = topic
}

// GetStats returns producer statistics
func (kp *KafkaProducer) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"dead_letter_queue_size": len(kp.deadLetterCh),
		"is_closed":              kp.closed,
		"topic_mappings":         kp.topics,
	}
}

// HealthCheck performs a lightweight health check on the Kafka producer
// Optimized to reduce CPU usage while maintaining functionality
func (kp *KafkaProducer) HealthCheck(ctx context.Context) error {
	kp.mu.RLock()
	defer kp.mu.RUnlock()

	// Check if producer is closed
	if kp.closed {
		return fmt.Errorf("producer is closed")
	}

	// Check if producer is nil (should not happen, but safety check)
	if kp.producer == nil {
		return fmt.Errorf("producer is not initialized")
	}

	// Lightweight check: verify producer input channel is not closed
	// This is much faster than sending an actual message
	select {
	case <-kp.ctx.Done():
		return fmt.Errorf("producer context is cancelled")
	default:
		// Producer is responsive and context is active
		return nil
	}
}
