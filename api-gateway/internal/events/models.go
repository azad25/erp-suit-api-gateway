package events

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"erp-api-gateway/internal/interfaces"
)

// Business event models with proper metadata

// UserLoggedInEvent represents a user login event
type UserLoggedInEvent struct {
	UserID        string    `json:"user_id"`
	Email         string    `json:"email"`
	IPAddress     string    `json:"ip_address"`
	UserAgent     string    `json:"user_agent"`
	LoginTime     time.Time `json:"login_time"`
	SessionID     string    `json:"session_id"`
	RememberMe    bool      `json:"remember_me"`
	LoginMethod   string    `json:"login_method"` // "password", "oauth", "sso"
	DeviceInfo    string    `json:"device_info,omitempty"`
	Location      string    `json:"location,omitempty"`
}

// UserRegisteredEvent represents a user registration event
type UserRegisteredEvent struct {
	UserID           string    `json:"user_id"`
	Email            string    `json:"email"`
	FirstName        string    `json:"first_name"`
	LastName         string    `json:"last_name"`
	RegistrationTime time.Time `json:"registration_time"`
	IPAddress        string    `json:"ip_address"`
	UserAgent        string    `json:"user_agent"`
	RegistrationSource string  `json:"registration_source"` // "web", "mobile", "api"
	EmailVerified    bool      `json:"email_verified"`
	OrganizationID   string    `json:"organization_id,omitempty"`
	InvitedBy        string    `json:"invited_by,omitempty"`
}

// UserLoggedOutEvent represents a user logout event
type UserLoggedOutEvent struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	LogoutTime  time.Time `json:"logout_time"`
	SessionID   string    `json:"session_id"`
	LogoutType  string    `json:"logout_type"` // "manual", "timeout", "forced"
	IPAddress   string    `json:"ip_address"`
	SessionDuration time.Duration `json:"session_duration"`
}

// TokenRefreshedEvent represents a token refresh event
type TokenRefreshedEvent struct {
	UserID         string    `json:"user_id"`
	Email          string    `json:"email"`
	RefreshTime    time.Time `json:"refresh_time"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	OldTokenID     string    `json:"old_token_id"`
	NewTokenID     string    `json:"new_token_id"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// APIRequestEvent represents an API request event
type APIRequestEvent struct {
	RequestID      string        `json:"request_id"`
	UserID         string        `json:"user_id,omitempty"`
	Method         string        `json:"method"`
	Path           string        `json:"path"`
	StatusCode     int           `json:"status_code"`
	Duration       time.Duration `json:"duration"`
	IPAddress      string        `json:"ip_address"`
	UserAgent      string        `json:"user_agent"`
	RequestTime    time.Time     `json:"request_time"`
	ResponseSize   int64         `json:"response_size"`
	RequestSize    int64         `json:"request_size"`
	Endpoint       string        `json:"endpoint"`
	QueryParams    string        `json:"query_params,omitempty"`
	ErrorMessage   string        `json:"error_message,omitempty"`
}

// APIErrorEvent represents an API error event
type APIErrorEvent struct {
	RequestID    string    `json:"request_id"`
	UserID       string    `json:"user_id,omitempty"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	StatusCode   int       `json:"status_code"`
	ErrorType    string    `json:"error_type"`
	ErrorMessage string    `json:"error_message"`
	ErrorCode    string    `json:"error_code,omitempty"`
	StackTrace   string    `json:"stack_trace,omitempty"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	ErrorTime    time.Time `json:"error_time"`
	Context      map[string]interface{} `json:"context,omitempty"`
}

// SystemAlertEvent represents a system alert event
type SystemAlertEvent struct {
	AlertID     string                 `json:"alert_id"`
	AlertType   string                 `json:"alert_type"` // "error", "warning", "info", "critical"
	Service     string                 `json:"service"`
	Component   string                 `json:"component"`
	Message     string                 `json:"message"`
	Severity    string                 `json:"severity"` // "low", "medium", "high", "critical"
	AlertTime   time.Time              `json:"alert_time"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy  string                 `json:"resolved_by,omitempty"`
}

// EventBuilder provides helper methods to create events with proper metadata
type EventBuilder struct {
	source        string
	version       string
	correlationID string
}

// NewEventBuilder creates a new event builder
func NewEventBuilder(source, version string) *EventBuilder {
	return &EventBuilder{
		source:  source,
		version: version,
	}
}

// WithCorrelationID sets the correlation ID for events
func (eb *EventBuilder) WithCorrelationID(correlationID string) *EventBuilder {
	eb.correlationID = correlationID
	return eb
}

// BuildUserLoggedInEvent creates a UserLoggedIn event
func (eb *EventBuilder) BuildUserLoggedInEvent(data UserLoggedInEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeUserLoggedIn,
		UserID:        data.UserID,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// BuildUserRegisteredEvent creates a UserRegistered event
func (eb *EventBuilder) BuildUserRegisteredEvent(data UserRegisteredEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeUserRegistered,
		UserID:        data.UserID,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// BuildUserLoggedOutEvent creates a UserLoggedOut event
func (eb *EventBuilder) BuildUserLoggedOutEvent(data UserLoggedOutEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeUserLoggedOut,
		UserID:        data.UserID,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// BuildTokenRefreshedEvent creates a TokenRefreshed event
func (eb *EventBuilder) BuildTokenRefreshedEvent(data TokenRefreshedEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeTokenRefreshed,
		UserID:        data.UserID,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// BuildAPIRequestEvent creates an APIRequest event
func (eb *EventBuilder) BuildAPIRequestEvent(data APIRequestEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeAPIRequest,
		UserID:        data.UserID,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// BuildAPIErrorEvent creates an APIError event
func (eb *EventBuilder) BuildAPIErrorEvent(data APIErrorEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeAPIError,
		UserID:        data.UserID,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// BuildSystemAlertEvent creates a SystemAlert event
func (eb *EventBuilder) BuildSystemAlertEvent(data SystemAlertEvent) interfaces.Event {
	return interfaces.Event{
		ID:            generateEventID(),
		Type:          interfaces.EventTypeSystemAlert,
		Data:          structToMap(data),
		Timestamp:     time.Now().UTC(),
		CorrelationID: eb.correlationID,
		Source:        eb.source,
		Version:       eb.version,
	}
}

// Helper functions

// generateEventID generates a unique event ID
func generateEventID() string {
	return uuid.New().String()
}

// structToMap converts a struct to map[string]interface{}
func structToMap(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	
	// Convert struct to JSON and back to map for simplicity
	jsonData, err := json.Marshal(data)
	if err != nil {
		return result
	}
	
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return result
	}
	
	return result
}