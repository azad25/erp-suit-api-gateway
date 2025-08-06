package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/events"
	"erp-api-gateway/internal/interfaces"
	"erp-api-gateway/internal/services"
)

func main() {
	// Load configuration
	cfg := &config.KafkaConfig{
		Brokers:       []string{"localhost:9092"},
		ClientID:      "erp-api-gateway-example",
		RetryMax:      3,
		RetryBackoff:  100 * time.Millisecond,
		FlushMessages: 10,
		FlushBytes:    1024,
		FlushTimeout:  1 * time.Second,
	}

	// Create Kafka producer
	producer, err := services.NewKafkaProducer(cfg)
	if err != nil {
		log.Fatalf("Failed to create Kafka producer: %v", err)
	}
	defer producer.Close()

	// Create event builder
	builder := events.NewEventBuilder("erp-api-gateway", "1.0")
	builder.WithCorrelationID("example-correlation-123")

	// Example 1: User Login Event
	fmt.Println("Publishing user login event...")
	loginEvent := builder.BuildUserLoggedInEvent(events.UserLoggedInEvent{
		UserID:      "user-123",
		Email:       "john.doe@example.com",
		IPAddress:   "192.168.1.100",
		UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		LoginTime:   time.Now().UTC(),
		SessionID:   "session-abc123",
		RememberMe:  true,
		LoginMethod: "password",
		DeviceInfo:  "MacBook Pro",
		Location:    "San Francisco, CA",
	})

	if err := producer.PublishEvent(context.Background(), loginEvent); err != nil {
		log.Printf("Failed to publish login event: %v", err)
	} else {
		fmt.Printf("✓ Published login event: %s\n", loginEvent.ID)
	}

	// Example 2: User Registration Event
	fmt.Println("Publishing user registration event...")
	registrationEvent := builder.BuildUserRegisteredEvent(events.UserRegisteredEvent{
		UserID:             "user-456",
		Email:              "jane.smith@example.com",
		FirstName:          "Jane",
		LastName:           "Smith",
		RegistrationTime:   time.Now().UTC(),
		IPAddress:          "192.168.1.101",
		UserAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		RegistrationSource: "web",
		EmailVerified:      false,
		OrganizationID:     "org-789",
		InvitedBy:          "user-123",
	})

	if err := producer.PublishEvent(context.Background(), registrationEvent); err != nil {
		log.Printf("Failed to publish registration event: %v", err)
	} else {
		fmt.Printf("✓ Published registration event: %s\n", registrationEvent.ID)
	}

	// Example 3: API Request Event
	fmt.Println("Publishing API request event...")
	apiEvent := builder.BuildAPIRequestEvent(events.APIRequestEvent{
		RequestID:    "req-789",
		UserID:       "user-123",
		Method:       "GET",
		Path:         "/api/user/profile",
		StatusCode:   200,
		Duration:     45 * time.Millisecond,
		IPAddress:    "192.168.1.100",
		UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		RequestTime:  time.Now().UTC(),
		ResponseSize: 2048,
		RequestSize:  256,
		Endpoint:     "user.profile",
		QueryParams:  "include=preferences",
	})

	if err := producer.PublishEvent(context.Background(), apiEvent); err != nil {
		log.Printf("Failed to publish API event: %v", err)
	} else {
		fmt.Printf("✓ Published API event: %s\n", apiEvent.ID)
	}

	// Example 4: System Alert Event
	fmt.Println("Publishing system alert event...")
	alertEvent := builder.BuildSystemAlertEvent(events.SystemAlertEvent{
		AlertID:   "alert-456",
		AlertType: "warning",
		Service:   "api-gateway",
		Component: "auth-middleware",
		Message:   "High response time detected",
		Severity:  "medium",
		AlertTime: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"avg_response_time": 250.5,
			"threshold":         200.0,
			"duration":          "5m",
			"affected_endpoints": []string{"/api/auth/login", "/api/auth/register"},
		},
		Resolved: false,
	})

	if err := producer.PublishEvent(context.Background(), alertEvent); err != nil {
		log.Printf("Failed to publish alert event: %v", err)
	} else {
		fmt.Printf("✓ Published alert event: %s\n", alertEvent.ID)
	}

	// Example 5: Batch Publishing
	fmt.Println("Publishing batch of events...")
	batchEvents := []interfaces.Event{
		builder.BuildAPIRequestEvent(events.APIRequestEvent{
			RequestID:   "req-batch-1",
			UserID:      "user-123",
			Method:      "POST",
			Path:        "/api/data/create",
			StatusCode:  201,
			Duration:    120 * time.Millisecond,
			RequestTime: time.Now().UTC(),
		}),
		builder.BuildAPIRequestEvent(events.APIRequestEvent{
			RequestID:   "req-batch-2",
			UserID:      "user-456",
			Method:      "PUT",
			Path:        "/api/data/update",
			StatusCode:  200,
			Duration:    85 * time.Millisecond,
			RequestTime: time.Now().UTC(),
		}),
		builder.BuildAPIRequestEvent(events.APIRequestEvent{
			RequestID:   "req-batch-3",
			UserID:      "user-789",
			Method:      "DELETE",
			Path:        "/api/data/delete",
			StatusCode:  204,
			Duration:    30 * time.Millisecond,
			RequestTime: time.Now().UTC(),
		}),
	}

	if err := producer.PublishBatch(context.Background(), batchEvents); err != nil {
		log.Printf("Failed to publish batch events: %v", err)
	} else {
		fmt.Printf("✓ Published batch of %d events\n", len(batchEvents))
	}

	// Example 6: Health Check
	fmt.Println("Performing health check...")
	if err := producer.HealthCheck(context.Background()); err != nil {
		log.Printf("Health check failed: %v", err)
	} else {
		fmt.Println("✓ Health check passed")
	}

	// Example 7: Get Producer Stats
	fmt.Println("Getting producer statistics...")
	stats := producer.GetStats()
	fmt.Printf("Producer Stats:\n")
	fmt.Printf("  Dead Letter Queue Size: %v\n", stats["dead_letter_queue_size"])
	fmt.Printf("  Is Closed: %v\n", stats["is_closed"])
	fmt.Printf("  Topic Mappings: %v\n", stats["topic_mappings"])

	// Example 8: Custom Topic Mapping
	fmt.Println("Setting custom topic mapping...")
	producer.SetTopicMapping("custom.event", "custom-topic")
	customTopic := producer.GetTopicForEventType("custom.event")
	fmt.Printf("✓ Custom event type 'custom.event' maps to topic: %s\n", customTopic)

	// Wait a bit for async operations to complete
	fmt.Println("Waiting for async operations to complete...")
	time.Sleep(2 * time.Second)

	fmt.Println("Example completed successfully!")
}