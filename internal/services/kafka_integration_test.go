package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/events"
	"erp-api-gateway/internal/interfaces"
)

// TestKafkaProducer_Integration tests the integration between Kafka producer and event models
func TestKafkaProducer_Integration(t *testing.T) {
	// Skip this test if running in CI or without Kafka
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test would require a running Kafka instance
	// For now, we'll test the integration with mock producer
	t.Run("with_event_builder", func(t *testing.T) {
		// Create event builder
		builder := events.NewEventBuilder("erp-api-gateway", "1.0")
		builder.WithCorrelationID("test-correlation-123")

		// Create user login event
		loginData := events.UserLoggedInEvent{
			UserID:      "user-123",
			Email:       "test@example.com",
			IPAddress:   "192.168.1.1",
			UserAgent:   "Mozilla/5.0",
			LoginTime:   time.Now().UTC(),
			SessionID:   "session-123",
			RememberMe:  true,
			LoginMethod: "password",
			DeviceInfo:  "Desktop",
			Location:    "New York",
		}

		event := builder.BuildUserLoggedInEvent(loginData)

		// Verify event structure
		assert.NotEmpty(t, event.ID)
		assert.Equal(t, interfaces.EventTypeUserLoggedIn, event.Type)
		assert.Equal(t, loginData.UserID, event.UserID)
		assert.Equal(t, "test-correlation-123", event.CorrelationID)
		assert.Equal(t, "erp-api-gateway", event.Source)
		assert.Equal(t, "1.0", event.Version)
		assert.NotNil(t, event.Data)

		// Verify data contains all expected fields
		expectedFields := []string{
			"user_id", "email", "ip_address", "user_agent",
			"login_time", "session_id", "remember_me", "login_method",
			"device_info", "location",
		}

		for _, field := range expectedFields {
			assert.Contains(t, event.Data, field, "Event data should contain field: %s", field)
		}
	})

	t.Run("multiple_event_types", func(t *testing.T) {
		builder := events.NewEventBuilder("erp-api-gateway", "1.0")
		builder.WithCorrelationID("test-correlation-456")

		// Test different event types
		events := []interfaces.Event{
			builder.BuildUserLoggedInEvent(events.UserLoggedInEvent{
				UserID:      "user-123",
				Email:       "test@example.com",
				LoginTime:   time.Now().UTC(),
				SessionID:   "session-123",
				LoginMethod: "password",
			}),
			builder.BuildUserRegisteredEvent(events.UserRegisteredEvent{
				UserID:             "user-456",
				Email:              "newuser@example.com",
				FirstName:          "John",
				LastName:           "Doe",
				RegistrationTime:   time.Now().UTC(),
				RegistrationSource: "web",
				EmailVerified:      false,
			}),
			builder.BuildAPIRequestEvent(events.APIRequestEvent{
				RequestID:   "req-123",
				UserID:      "user-123",
				Method:      "POST",
				Path:        "/api/auth/login",
				StatusCode:  200,
				Duration:    150 * time.Millisecond,
				RequestTime: time.Now().UTC(),
			}),
		}

		// Verify all events have proper structure
		for i, event := range events {
			assert.NotEmpty(t, event.ID, "Event %d should have ID", i)
			assert.NotEmpty(t, event.Type, "Event %d should have type", i)
			assert.Equal(t, "test-correlation-456", event.CorrelationID, "Event %d should have correlation ID", i)
			assert.Equal(t, "erp-api-gateway", event.Source, "Event %d should have source", i)
			assert.Equal(t, "1.0", event.Version, "Event %d should have version", i)
			assert.NotNil(t, event.Data, "Event %d should have data", i)
		}

		// Verify event types are correct
		assert.Equal(t, interfaces.EventTypeUserLoggedIn, events[0].Type)
		assert.Equal(t, interfaces.EventTypeUserRegistered, events[1].Type)
		assert.Equal(t, interfaces.EventTypeAPIRequest, events[2].Type)
	})
}

// TestKafkaProducer_EventPublishing tests event publishing scenarios
func TestKafkaProducer_EventPublishing(t *testing.T) {
	// This would be a real integration test with Kafka
	// For now, we'll simulate the scenario
	t.Run("correlation_id_tracking", func(t *testing.T) {
		builder := events.NewEventBuilder("erp-api-gateway", "1.0")
		correlationID := "correlation-789"
		builder.WithCorrelationID(correlationID)

		// Create multiple related events
		loginEvent := builder.BuildUserLoggedInEvent(events.UserLoggedInEvent{
			UserID:      "user-123",
			Email:       "test@example.com",
			LoginTime:   time.Now().UTC(),
			SessionID:   "session-123",
			LoginMethod: "password",
		})

		apiEvent := builder.BuildAPIRequestEvent(events.APIRequestEvent{
			RequestID:   "req-123",
			UserID:      "user-123",
			Method:      "GET",
			Path:        "/api/user/profile",
			StatusCode:  200,
			Duration:    50 * time.Millisecond,
			RequestTime: time.Now().UTC(),
		})

		// Both events should have the same correlation ID
		assert.Equal(t, correlationID, loginEvent.CorrelationID)
		assert.Equal(t, correlationID, apiEvent.CorrelationID)

		// Both events should have the same user ID
		assert.Equal(t, "user-123", loginEvent.UserID)
		assert.Equal(t, "user-123", apiEvent.UserID)
	})

	t.Run("event_metadata", func(t *testing.T) {
		builder := events.NewEventBuilder("erp-api-gateway", "1.0")
		
		event := builder.BuildSystemAlertEvent(events.SystemAlertEvent{
			AlertID:   "alert-123",
			AlertType: "error",
			Service:   "api-gateway",
			Component: "auth-middleware",
			Message:   "High error rate detected",
			Severity:  "high",
			AlertTime: time.Now().UTC(),
			Metadata: map[string]interface{}{
				"error_rate": 0.15,
				"threshold":  0.10,
				"duration":   "5m",
			},
			Resolved: false,
		})

		// Verify event metadata
		assert.NotEmpty(t, event.ID)
		assert.Equal(t, interfaces.EventTypeSystemAlert, event.Type)
		assert.Empty(t, event.UserID) // System alerts don't have user ID
		assert.Equal(t, "erp-api-gateway", event.Source)
		assert.Equal(t, "1.0", event.Version)
		assert.WithinDuration(t, time.Now().UTC(), event.Timestamp, time.Second)

		// Verify alert-specific data
		assert.Equal(t, "alert-123", event.Data["alert_id"])
		assert.Equal(t, "error", event.Data["alert_type"])
		assert.Equal(t, "high", event.Data["severity"])
		assert.Equal(t, false, event.Data["resolved"])
		
		// Verify nested metadata
		metadata, ok := event.Data["metadata"].(map[string]interface{})
		require.True(t, ok, "Metadata should be a map")
		assert.Equal(t, 0.15, metadata["error_rate"])
		assert.Equal(t, 0.10, metadata["threshold"])
		assert.Equal(t, "5m", metadata["duration"])
	})
}

// TestKafkaProducer_TopicMapping tests topic mapping functionality
func TestKafkaProducer_TopicMapping(t *testing.T) {
	cfg := &config.KafkaConfig{
		Brokers:       []string{"localhost:9092"},
		ClientID:      "test-client",
		RetryMax:      3,
		RetryBackoff:  100 * time.Millisecond,
		FlushMessages: 100,
		FlushBytes:    1024,
		FlushTimeout:  1 * time.Second,
	}

	// This would normally create a real producer, but we'll test the mapping logic
	producer := &KafkaProducer{
		config: cfg,
		topics: make(map[string]string),
	}
	producer.setupTopicMappings()

	tests := []struct {
		eventType     string
		expectedTopic string
	}{
		{interfaces.EventTypeUserLoggedIn, "user-events"},
		{interfaces.EventTypeUserRegistered, "user-events"},
		{interfaces.EventTypeUserLoggedOut, "user-events"},
		{interfaces.EventTypeTokenRefreshed, "auth-events"},
		{interfaces.EventTypeAPIRequest, "api-events"},
		{interfaces.EventTypeAPIError, "error-events"},
		{interfaces.EventTypeSystemAlert, "system-events"},
		{"unknown.event", "default-events"},
	}

	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			topic := producer.GetTopicForEventType(tt.eventType)
			assert.Equal(t, tt.expectedTopic, topic)
		})
	}
}

// TestKafkaProducer_ErrorHandling tests error handling scenarios
func TestKafkaProducer_ErrorHandling(t *testing.T) {
	t.Run("dead_letter_queue_message", func(t *testing.T) {
		event := interfaces.Event{
			ID:            "failed-event-123",
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
			Topic:         "user-events",
			FailureReason: "broker not available",
			AttemptCount:  3,
			FirstAttempt:  time.Now().Add(-5 * time.Minute),
			LastAttempt:   time.Now(),
		}

		// Verify dead letter message structure
		assert.Equal(t, event.ID, deadLetter.Event.ID)
		assert.Equal(t, "user-events", deadLetter.Topic)
		assert.Equal(t, "broker not available", deadLetter.FailureReason)
		assert.Equal(t, 3, deadLetter.AttemptCount)
		assert.True(t, deadLetter.LastAttempt.After(deadLetter.FirstAttempt))
	})
}