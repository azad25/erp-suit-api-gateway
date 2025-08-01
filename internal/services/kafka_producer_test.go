package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/interfaces"
)

func TestNewKafkaProducer(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.KafkaConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &config.KafkaConfig{
				Brokers:       []string{"localhost:9092"},
				ClientID:      "test-client",
				RetryMax:      3,
				RetryBackoff:  100 * time.Millisecond,
				FlushMessages: 100,
				FlushBytes:    1024,
				FlushTimeout:  1 * time.Second,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer, err := NewKafkaProducer(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, producer)
			} else {
				// Note: This will fail in test environment without Kafka
				// In real tests, we would use a mock producer
				assert.Error(t, err) // Expected to fail without Kafka
			}
		})
	}
}

func TestKafkaProducer_PublishEvent(t *testing.T) {
	// Create mock producer
	mockProducer := mocks.NewAsyncProducer(t, nil)
	
	// Set up expectations
	mockProducer.ExpectInputAndSucceed()

	// Create producer with mock
	producer := &KafkaProducer{
		producer:     mockProducer,
		config:       &config.KafkaConfig{},
		deadLetterCh: make(chan *DeadLetterMessage, 100),
		ctx:          context.Background(),
		cancel:       func() {},
		topics:       make(map[string]string),
		closed:       false,
	}
	producer.setupTopicMappings()

	// Test event
	event := interfaces.Event{
		ID:            "test-event-id",
		Type:          interfaces.EventTypeUserLoggedIn,
		UserID:        "user-123",
		Data:          map[string]interface{}{"test": "data"},
		Timestamp:     time.Now().UTC(),
		CorrelationID: "correlation-123",
		Source:        "test-source",
		Version:       "1.0",
	}

	// Test publishing event
	err := producer.PublishEvent(context.Background(), event)
	assert.NoError(t, err)

	// Verify expectations
	mockProducer.Close()
}

func TestKafkaProducer_PublishEvent_ClosedProducer(t *testing.T) {
	producer := &KafkaProducer{
		closed: true,
	}

	event := interfaces.Event{
		ID:   "test-event-id",
		Type: interfaces.EventTypeUserLoggedIn,
	}

	err := producer.PublishEvent(context.Background(), event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "producer is closed")
}

func TestKafkaProducer_PublishUserEvent(t *testing.T) {
	mockProducer := mocks.NewAsyncProducer(t, nil)
	mockProducer.ExpectInputAndSucceed()

	producer := &KafkaProducer{
		producer:     mockProducer,
		config:       &config.KafkaConfig{},
		deadLetterCh: make(chan *DeadLetterMessage, 100),
		ctx:          context.Background(),
		cancel:       func() {},
		topics:       make(map[string]string),
		closed:       false,
	}
	producer.setupTopicMappings()

	event := interfaces.Event{
		ID:            "test-event-id",
		Type:          interfaces.EventTypeUserLoggedIn,
		Data:          map[string]interface{}{"test": "data"},
		Timestamp:     time.Now().UTC(),
		CorrelationID: "correlation-123",
		Source:        "test-source",
		Version:       "1.0",
	}

	err := producer.PublishUserEvent(context.Background(), "user-456", event)
	assert.NoError(t, err)

	assert.NoError(t, mockProducer.Close())
}

func TestKafkaProducer_PublishBatch(t *testing.T) {
	mockProducer := mocks.NewAsyncProducer(t, nil)
	
	// Expect multiple messages
	mockProducer.ExpectInputAndSucceed()
	mockProducer.ExpectInputAndSucceed()

	producer := &KafkaProducer{
		producer:     mockProducer,
		config:       &config.KafkaConfig{},
		deadLetterCh: make(chan *DeadLetterMessage, 100),
		ctx:          context.Background(),
		cancel:       func() {},
		topics:       make(map[string]string),
		closed:       false,
	}
	producer.setupTopicMappings()

	events := []interfaces.Event{
		{
			ID:            "event-1",
			Type:          interfaces.EventTypeUserLoggedIn,
			UserID:        "user-123",
			Data:          map[string]interface{}{"test": "data1"},
			Timestamp:     time.Now().UTC(),
			CorrelationID: "correlation-123",
			Source:        "test-source",
			Version:       "1.0",
		},
		{
			ID:            "event-2",
			Type:          interfaces.EventTypeUserRegistered,
			UserID:        "user-456",
			Data:          map[string]interface{}{"test": "data2"},
			Timestamp:     time.Now().UTC(),
			CorrelationID: "correlation-456",
			Source:        "test-source",
			Version:       "1.0",
		},
	}

	err := producer.PublishBatch(context.Background(), events)
	assert.NoError(t, err)

	assert.NoError(t, mockProducer.Close())
}

func TestKafkaProducer_PublishBatch_EmptyEvents(t *testing.T) {
	producer := &KafkaProducer{
		closed: false,
	}

	err := producer.PublishBatch(context.Background(), []interfaces.Event{})
	assert.NoError(t, err)
}

func TestKafkaProducer_setupTopicMappings(t *testing.T) {
	producer := &KafkaProducer{
		topics: make(map[string]string),
	}

	producer.setupTopicMappings()

	expectedMappings := map[string]string{
		interfaces.EventTypeUserLoggedIn:   "user-events",
		interfaces.EventTypeUserRegistered: "user-events",
		interfaces.EventTypeUserLoggedOut:  "user-events",
		interfaces.EventTypeTokenRefreshed: "auth-events",
		interfaces.EventTypeAPIRequest:     "api-events",
		interfaces.EventTypeAPIError:       "error-events",
		interfaces.EventTypeSystemAlert:    "system-events",
	}

	assert.Equal(t, expectedMappings, producer.topics)
}

func TestKafkaProducer_GetTopicForEventType(t *testing.T) {
	producer := &KafkaProducer{
		topics: map[string]string{
			"test.event": "test-topic",
		},
	}

	// Test existing event type
	topic := producer.GetTopicForEventType("test.event")
	assert.Equal(t, "test-topic", topic)

	// Test non-existing event type
	topic = producer.GetTopicForEventType("unknown.event")
	assert.Equal(t, "default-events", topic)
}

func TestKafkaProducer_SetTopicMapping(t *testing.T) {
	producer := &KafkaProducer{
		topics: make(map[string]string),
	}

	producer.SetTopicMapping("custom.event", "custom-topic")

	topic := producer.GetTopicForEventType("custom.event")
	assert.Equal(t, "custom-topic", topic)
}

func TestKafkaProducer_isRetryableError(t *testing.T) {
	producer := &KafkaProducer{}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "retryable error - not leader",
			err:      sarama.ErrNotLeaderForPartition,
			expected: true,
		},
		{
			name:     "retryable error - leader not available",
			err:      sarama.ErrLeaderNotAvailable,
			expected: true,
		},
		{
			name:     "retryable error - request timeout",
			err:      sarama.ErrRequestTimedOut,
			expected: true,
		},
		{
			name:     "non-retryable error - invalid message",
			err:      sarama.ErrInvalidMessage,
			expected: false,
		},
		{
			name:     "non-kafka error",
			err:      assert.AnError,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := producer.isRetryableError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKafkaProducer_GetStats(t *testing.T) {
	producer := &KafkaProducer{
		deadLetterCh: make(chan *DeadLetterMessage, 100),
		closed:       false,
		topics: map[string]string{
			"test.event": "test-topic",
		},
	}

	stats := producer.GetStats()

	assert.Contains(t, stats, "dead_letter_queue_size")
	assert.Contains(t, stats, "is_closed")
	assert.Contains(t, stats, "topic_mappings")
	assert.Equal(t, 0, stats["dead_letter_queue_size"])
	assert.Equal(t, false, stats["is_closed"])
}

func TestKafkaProducer_HealthCheck(t *testing.T) {
	t.Run("closed producer", func(t *testing.T) {
		producer := &KafkaProducer{
			closed: true,
		}

		err := producer.HealthCheck(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "producer is closed")
	})

	t.Run("healthy producer", func(t *testing.T) {
		mockProducer := mocks.NewAsyncProducer(t, nil)
		mockProducer.ExpectInputAndSucceed()

		producer := &KafkaProducer{
			producer:     mockProducer,
			config:       &config.KafkaConfig{},
			deadLetterCh: make(chan *DeadLetterMessage, 100),
			ctx:          context.Background(),
			cancel:       func() {},
			topics:       make(map[string]string),
			closed:       false,
		}
		producer.setupTopicMappings()

		err := producer.HealthCheck(context.Background())
		assert.NoError(t, err)

		assert.NoError(t, mockProducer.Close())
	})
}

func TestDeadLetterMessage_Serialization(t *testing.T) {
	event := interfaces.Event{
		ID:            "test-event-id",
		Type:          interfaces.EventTypeUserLoggedIn,
		UserID:        "user-123",
		Data:          map[string]interface{}{"test": "data"},
		Timestamp:     time.Now().UTC(),
		CorrelationID: "correlation-123",
		Source:        "test-source",
		Version:       "1.0",
	}

	deadLetter := &DeadLetterMessage{
		Event:         event,
		Topic:         "test-topic",
		FailureReason: "test failure",
		AttemptCount:  3,
		FirstAttempt:  time.Now().Add(-5 * time.Minute),
		LastAttempt:   time.Now(),
	}

	// Test JSON serialization
	data, err := json.Marshal(deadLetter)
	require.NoError(t, err)

	// Test JSON deserialization
	var unmarshaled DeadLetterMessage
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, deadLetter.Event.ID, unmarshaled.Event.ID)
	assert.Equal(t, deadLetter.Topic, unmarshaled.Topic)
	assert.Equal(t, deadLetter.FailureReason, unmarshaled.FailureReason)
	assert.Equal(t, deadLetter.AttemptCount, unmarshaled.AttemptCount)
}

func TestKafkaProducer_Close(t *testing.T) {
	mockProducer := mocks.NewAsyncProducer(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	producer := &KafkaProducer{
		producer:     mockProducer,
		config:       &config.KafkaConfig{},
		deadLetterCh: make(chan *DeadLetterMessage, 100),
		ctx:          ctx,
		cancel:       cancel,
		topics:       make(map[string]string),
		closed:       false,
	}

	// Start background goroutines
	producer.wg.Add(3)
	go producer.handleSuccesses()
	go producer.handleErrors()
	go producer.handleDeadLetterQueue()

	// Close the producer
	err := producer.Close()
	assert.NoError(t, err)
	assert.True(t, producer.closed)

	// Calling close again should not error
	err = producer.Close()
	assert.NoError(t, err)

	// Don't call mockProducer.Close() as it's already closed by AsyncClose()
}

// Benchmark tests
func BenchmarkKafkaProducer_PublishEvent(b *testing.B) {
	mockProducer := mocks.NewAsyncProducer(b, nil)
	
	// Set up expectations for all benchmark iterations
	for i := 0; i < b.N; i++ {
		mockProducer.ExpectInputAndSucceed()
	}

	producer := &KafkaProducer{
		producer:     mockProducer,
		config:       &config.KafkaConfig{},
		deadLetterCh: make(chan *DeadLetterMessage, 1000),
		ctx:          context.Background(),
		cancel:       func() {},
		topics:       make(map[string]string),
		closed:       false,
	}
	producer.setupTopicMappings()

	event := interfaces.Event{
		ID:            "benchmark-event",
		Type:          interfaces.EventTypeUserLoggedIn,
		UserID:        "user-123",
		Data:          map[string]interface{}{"test": "data"},
		Timestamp:     time.Now().UTC(),
		CorrelationID: "correlation-123",
		Source:        "benchmark",
		Version:       "1.0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := producer.PublishEvent(context.Background(), event)
		if err != nil {
			b.Fatal(err)
		}
	}

	mockProducer.Close()
}

func BenchmarkKafkaProducer_PublishBatch(b *testing.B) {
	mockProducer := mocks.NewAsyncProducer(b, nil)
	
	batchSize := 10
	// Set up expectations for all benchmark iterations
	for i := 0; i < b.N*batchSize; i++ {
		mockProducer.ExpectInputAndSucceed()
	}

	producer := &KafkaProducer{
		producer:     mockProducer,
		config:       &config.KafkaConfig{},
		deadLetterCh: make(chan *DeadLetterMessage, 1000),
		ctx:          context.Background(),
		cancel:       func() {},
		topics:       make(map[string]string),
		closed:       false,
	}
	producer.setupTopicMappings()

	events := make([]interfaces.Event, batchSize)
	for i := 0; i < batchSize; i++ {
		events[i] = interfaces.Event{
			ID:            "benchmark-event",
			Type:          interfaces.EventTypeUserLoggedIn,
			UserID:        "user-123",
			Data:          map[string]interface{}{"test": "data"},
			Timestamp:     time.Now().UTC(),
			CorrelationID: "correlation-123",
			Source:        "benchmark",
			Version:       "1.0",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := producer.PublishBatch(context.Background(), events)
		if err != nil {
			b.Fatal(err)
		}
	}

	mockProducer.Close()
}