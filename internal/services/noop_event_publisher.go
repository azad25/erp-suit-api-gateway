package services

import (
	"context"
	"log"

	"erp-api-gateway/internal/interfaces"
)

// NoOpEventPublisher is a no-operation event publisher that implements the EventPublisher interface
// It's used as a fallback when Kafka is not available
type NoOpEventPublisher struct{}

// NewNoOpEventPublisher creates a new no-operation event publisher
func NewNoOpEventPublisher() *NoOpEventPublisher {
	return &NoOpEventPublisher{}
}

// PublishEvent logs the event but doesn't actually publish it
func (n *NoOpEventPublisher) PublishEvent(ctx context.Context, event interfaces.Event) error {
	log.Printf("NoOpEventPublisher: Would publish event %s of type %s (Kafka unavailable)", event.ID, event.Type)
	return nil
}

// PublishUserEvent logs the event but doesn't actually publish it
func (n *NoOpEventPublisher) PublishUserEvent(ctx context.Context, userID string, event interfaces.Event) error {
	log.Printf("NoOpEventPublisher: Would publish user event %s for user %s of type %s (Kafka unavailable)", event.ID, userID, event.Type)
	return nil
}

// PublishBatch logs the events but doesn't actually publish them
func (n *NoOpEventPublisher) PublishBatch(ctx context.Context, events []interfaces.Event) error {
	log.Printf("NoOpEventPublisher: Would publish batch of %d events (Kafka unavailable)", len(events))
	return nil
}

// Close is a no-op for the no-operation publisher
func (n *NoOpEventPublisher) Close() error {
	log.Println("NoOpEventPublisher: Close called")
	return nil
}

// HealthCheck always returns nil for the no-operation publisher
func (n *NoOpEventPublisher) HealthCheck(ctx context.Context) error {
	return nil
}