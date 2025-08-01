package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"erp-api-gateway/internal/interfaces"
)

func TestEventBuilder_NewEventBuilder(t *testing.T) {
	source := "test-source"
	version := "1.0"

	builder := NewEventBuilder(source, version)

	assert.NotNil(t, builder)
	assert.Equal(t, source, builder.source)
	assert.Equal(t, version, builder.version)
	assert.Empty(t, builder.correlationID)
}

func TestEventBuilder_WithCorrelationID(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0")
	correlationID := "test-correlation-id"

	result := builder.WithCorrelationID(correlationID)

	assert.Equal(t, builder, result) // Should return same instance for chaining
	assert.Equal(t, correlationID, builder.correlationID)
}

func TestEventBuilder_BuildUserLoggedInEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := UserLoggedInEvent{
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

	event := builder.BuildUserLoggedInEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeUserLoggedIn, event.Type)
	assert.Equal(t, data.UserID, event.UserID)
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)
	assert.WithinDuration(t, time.Now().UTC(), event.Timestamp, time.Second)

	// Verify data contains expected fields
	assert.Equal(t, data.UserID, event.Data["user_id"])
	assert.Equal(t, data.Email, event.Data["email"])
	assert.Equal(t, data.IPAddress, event.Data["ip_address"])
}

func TestEventBuilder_BuildUserRegisteredEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := UserRegisteredEvent{
		UserID:             "user-456",
		Email:              "newuser@example.com",
		FirstName:          "John",
		LastName:           "Doe",
		RegistrationTime:   time.Now().UTC(),
		IPAddress:          "192.168.1.2",
		UserAgent:          "Mozilla/5.0",
		RegistrationSource: "web",
		EmailVerified:      false,
		OrganizationID:     "org-123",
		InvitedBy:          "user-789",
	}

	event := builder.BuildUserRegisteredEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeUserRegistered, event.Type)
	assert.Equal(t, data.UserID, event.UserID)
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)

	// Verify data contains expected fields
	assert.Equal(t, data.UserID, event.Data["user_id"])
	assert.Equal(t, data.Email, event.Data["email"])
	assert.Equal(t, data.FirstName, event.Data["first_name"])
	assert.Equal(t, data.LastName, event.Data["last_name"])
}

func TestEventBuilder_BuildUserLoggedOutEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := UserLoggedOutEvent{
		UserID:          "user-123",
		Email:           "test@example.com",
		LogoutTime:      time.Now().UTC(),
		SessionID:       "session-123",
		LogoutType:      "manual",
		IPAddress:       "192.168.1.1",
		SessionDuration: 30 * time.Minute,
	}

	event := builder.BuildUserLoggedOutEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeUserLoggedOut, event.Type)
	assert.Equal(t, data.UserID, event.UserID)
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)

	// Verify data contains expected fields
	assert.Equal(t, data.UserID, event.Data["user_id"])
	assert.Equal(t, data.LogoutType, event.Data["logout_type"])
	assert.Equal(t, data.SessionID, event.Data["session_id"])
}

func TestEventBuilder_BuildTokenRefreshedEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := TokenRefreshedEvent{
		UserID:         "user-123",
		Email:          "test@example.com",
		RefreshTime:    time.Now().UTC(),
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0",
		OldTokenID:     "old-token-123",
		NewTokenID:     "new-token-456",
		TokenExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
	}

	event := builder.BuildTokenRefreshedEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeTokenRefreshed, event.Type)
	assert.Equal(t, data.UserID, event.UserID)
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)

	// Verify data contains expected fields
	assert.Equal(t, data.UserID, event.Data["user_id"])
	assert.Equal(t, data.OldTokenID, event.Data["old_token_id"])
	assert.Equal(t, data.NewTokenID, event.Data["new_token_id"])
}

func TestEventBuilder_BuildAPIRequestEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := APIRequestEvent{
		RequestID:    "req-123",
		UserID:       "user-123",
		Method:       "POST",
		Path:         "/api/auth/login",
		StatusCode:   200,
		Duration:     150 * time.Millisecond,
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
		RequestTime:  time.Now().UTC(),
		ResponseSize: 1024,
		RequestSize:  512,
		Endpoint:     "auth.login",
		QueryParams:  "remember=true",
	}

	event := builder.BuildAPIRequestEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeAPIRequest, event.Type)
	assert.Equal(t, data.UserID, event.UserID)
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)

	// Verify data contains expected fields
	assert.Equal(t, data.RequestID, event.Data["request_id"])
	assert.Equal(t, data.Method, event.Data["method"])
	assert.Equal(t, data.Path, event.Data["path"])
	assert.Equal(t, float64(data.StatusCode), event.Data["status_code"]) // JSON numbers are float64
}

func TestEventBuilder_BuildAPIErrorEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := APIErrorEvent{
		RequestID:    "req-123",
		UserID:       "user-123",
		Method:       "POST",
		Path:         "/api/auth/login",
		StatusCode:   400,
		ErrorType:    "validation_error",
		ErrorMessage: "Invalid credentials",
		ErrorCode:    "AUTH_001",
		StackTrace:   "stack trace here",
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
		ErrorTime:    time.Now().UTC(),
		Context: map[string]interface{}{
			"field": "password",
		},
	}

	event := builder.BuildAPIErrorEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeAPIError, event.Type)
	assert.Equal(t, data.UserID, event.UserID)
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)

	// Verify data contains expected fields
	assert.Equal(t, data.RequestID, event.Data["request_id"])
	assert.Equal(t, data.ErrorType, event.Data["error_type"])
	assert.Equal(t, data.ErrorMessage, event.Data["error_message"])
	assert.Equal(t, data.ErrorCode, event.Data["error_code"])
}

func TestEventBuilder_BuildSystemAlertEvent(t *testing.T) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")

	data := SystemAlertEvent{
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
		},
		Resolved:   false,
		ResolvedAt: nil,
		ResolvedBy: "",
	}

	event := builder.BuildSystemAlertEvent(data)

	assert.NotEmpty(t, event.ID)
	assert.Equal(t, interfaces.EventTypeSystemAlert, event.Type)
	assert.Empty(t, event.UserID) // System alerts don't have user ID
	assert.Equal(t, "test-correlation", event.CorrelationID)
	assert.Equal(t, "test-source", event.Source)
	assert.Equal(t, "1.0", event.Version)
	assert.NotNil(t, event.Data)

	// Verify data contains expected fields
	assert.Equal(t, data.AlertID, event.Data["alert_id"])
	assert.Equal(t, data.AlertType, event.Data["alert_type"])
	assert.Equal(t, data.Service, event.Data["service"])
	assert.Equal(t, data.Severity, event.Data["severity"])
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2) // Should generate unique IDs
	
	// Should be valid UUID format (36 characters with hyphens)
	assert.Len(t, id1, 36)
	assert.Contains(t, id1, "-")
}

func TestStructToMap(t *testing.T) {
	type TestStruct struct {
		StringField string            `json:"string_field"`
		IntField    int               `json:"int_field"`
		BoolField   bool              `json:"bool_field"`
		TimeField   time.Time         `json:"time_field"`
		MapField    map[string]string `json:"map_field"`
	}

	testTime := time.Now().UTC()
	testStruct := TestStruct{
		StringField: "test",
		IntField:    42,
		BoolField:   true,
		TimeField:   testTime,
		MapField: map[string]string{
			"key": "value",
		},
	}

	result := structToMap(testStruct)

	assert.NotNil(t, result)
	assert.Equal(t, "test", result["string_field"])
	assert.Equal(t, float64(42), result["int_field"]) // JSON numbers are float64
	assert.Equal(t, true, result["bool_field"])
	assert.NotNil(t, result["time_field"])
	assert.NotNil(t, result["map_field"])
}

func TestStructToMap_InvalidInput(t *testing.T) {
	// Test with a type that can't be marshaled to JSON
	invalidInput := make(chan int)

	result := structToMap(invalidInput)

	assert.NotNil(t, result)
	assert.Empty(t, result) // Should return empty map on error
}

func TestBusinessEventModels_JSONSerialization(t *testing.T) {
	tests := []struct {
		name  string
		event interface{}
	}{
		{
			name: "UserLoggedInEvent",
			event: UserLoggedInEvent{
				UserID:      "user-123",
				Email:       "test@example.com",
				IPAddress:   "192.168.1.1",
				UserAgent:   "Mozilla/5.0",
				LoginTime:   time.Now().UTC(),
				SessionID:   "session-123",
				RememberMe:  true,
				LoginMethod: "password",
			},
		},
		{
			name: "UserRegisteredEvent",
			event: UserRegisteredEvent{
				UserID:             "user-456",
				Email:              "newuser@example.com",
				FirstName:          "John",
				LastName:           "Doe",
				RegistrationTime:   time.Now().UTC(),
				IPAddress:          "192.168.1.2",
				UserAgent:          "Mozilla/5.0",
				RegistrationSource: "web",
				EmailVerified:      false,
			},
		},
		{
			name: "APIRequestEvent",
			event: APIRequestEvent{
				RequestID:    "req-123",
				UserID:       "user-123",
				Method:       "POST",
				Path:         "/api/auth/login",
				StatusCode:   200,
				Duration:     150 * time.Millisecond,
				IPAddress:    "192.168.1.1",
				UserAgent:    "Mozilla/5.0",
				RequestTime:  time.Now().UTC(),
				ResponseSize: 1024,
				RequestSize:  512,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.event)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Test JSON unmarshaling
			var unmarshaled map[string]interface{}
			err = json.Unmarshal(data, &unmarshaled)
			require.NoError(t, err)
			assert.NotEmpty(t, unmarshaled)
		})
	}
}

// Benchmark tests
func BenchmarkEventBuilder_BuildUserLoggedInEvent(b *testing.B) {
	builder := NewEventBuilder("test-source", "1.0").WithCorrelationID("test-correlation")
	data := UserLoggedInEvent{
		UserID:      "user-123",
		Email:       "test@example.com",
		IPAddress:   "192.168.1.1",
		UserAgent:   "Mozilla/5.0",
		LoginTime:   time.Now().UTC(),
		SessionID:   "session-123",
		RememberMe:  true,
		LoginMethod: "password",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = builder.BuildUserLoggedInEvent(data)
	}
}

func BenchmarkGenerateEventID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generateEventID()
	}
}

func BenchmarkStructToMap(b *testing.B) {
	data := UserLoggedInEvent{
		UserID:      "user-123",
		Email:       "test@example.com",
		IPAddress:   "192.168.1.1",
		UserAgent:   "Mozilla/5.0",
		LoginTime:   time.Now().UTC(),
		SessionID:   "session-123",
		RememberMe:  true,
		LoginMethod: "password",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = structToMap(data)
	}
}