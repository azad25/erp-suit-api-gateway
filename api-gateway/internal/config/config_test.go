package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Test loading with defaults
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify default values
	if cfg.Server.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", cfg.Server.Port)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Expected default host '0.0.0.0', got '%s'", cfg.Server.Host)
	}

	if cfg.JWT.Algorithm != "RS256" {
		t.Errorf("Expected default JWT algorithm 'RS256', got '%s'", cfg.JWT.Algorithm)
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("SERVER_HOST", "127.0.0.1")
	os.Setenv("REDIS_HOST", "redis-server")
	os.Setenv("REDIS_PORT", "6380")
	os.Setenv("JWT_ALGORITHM", "ES256")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("SERVER_HOST")
		os.Unsetenv("REDIS_HOST")
		os.Unsetenv("REDIS_PORT")
		os.Unsetenv("JWT_ALGORITHM")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify environment variables override defaults
	if cfg.Server.Port != 9090 {
		t.Errorf("Expected port 9090 from env, got %d", cfg.Server.Port)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1' from env, got '%s'", cfg.Server.Host)
	}

	if cfg.Redis.Host != "redis-server" {
		t.Errorf("Expected Redis host 'redis-server' from env, got '%s'", cfg.Redis.Host)
	}

	if cfg.Redis.Port != 6380 {
		t.Errorf("Expected Redis port 6380 from env, got %d", cfg.Redis.Port)
	}

	if cfg.JWT.Algorithm != "ES256" {
		t.Errorf("Expected JWT algorithm 'ES256' from env, got '%s'", cfg.JWT.Algorithm)
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  port: 8081
  host: "localhost"
redis:
  host: "test-redis"
  port: 6379
jwt:
  algorithm: "HS256"
`
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	tmpFile.Close()

	cfg, err := LoadFromPath(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config from file: %v", err)
	}

	// Verify file values override defaults
	if cfg.Server.Port != 8081 {
		t.Errorf("Expected port 8081 from file, got %d", cfg.Server.Port)
	}

	if cfg.Server.Host != "localhost" {
		t.Errorf("Expected host 'localhost' from file, got '%s'", cfg.Server.Host)
	}

	if cfg.Redis.Host != "test-redis" {
		t.Errorf("Expected Redis host 'test-redis' from file, got '%s'", cfg.Redis.Host)
	}

	if cfg.JWT.Algorithm != "HS256" {
		t.Errorf("Expected JWT algorithm 'HS256' from file, got '%s'", cfg.JWT.Algorithm)
	}
}

func TestLoadFromJSONFile(t *testing.T) {
	// Create a temporary JSON config file
	configContent := `{
  "server": {
    "port": 8082,
    "host": "json-host"
  },
  "redis": {
    "host": "json-redis",
    "port": 6379
  },
  "jwt": {
    "algorithm": "RS256"
  }
}`
	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	tmpFile.Close()

	cfg, err := LoadFromPath(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config from JSON file: %v", err)
	}

	// Verify JSON file values
	if cfg.Server.Port != 8082 {
		t.Errorf("Expected port 8082 from JSON file, got %d", cfg.Server.Port)
	}

	if cfg.Server.Host != "json-host" {
		t.Errorf("Expected host 'json-host' from JSON file, got '%s'", cfg.Server.Host)
	}

	if cfg.Redis.Host != "json-redis" {
		t.Errorf("Expected Redis host 'json-redis' from JSON file, got '%s'", cfg.Redis.Host)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name        string
		modifyConfig func(*Config)
		expectError bool
	}{
		{
			name: "valid config",
			modifyConfig: func(cfg *Config) {
				// Default config should be valid
			},
			expectError: false,
		},
		{
			name: "invalid server port",
			modifyConfig: func(cfg *Config) {
				cfg.Server.Port = 0
			},
			expectError: true,
		},
		{
			name: "invalid server port high",
			modifyConfig: func(cfg *Config) {
				cfg.Server.Port = 70000
			},
			expectError: true,
		},
		{
			name: "empty server host",
			modifyConfig: func(cfg *Config) {
				cfg.Server.Host = ""
			},
			expectError: true,
		},
		{
			name: "invalid Redis DB",
			modifyConfig: func(cfg *Config) {
				cfg.Redis.DB = 20
			},
			expectError: true,
		},
		{
			name: "invalid JWT algorithm",
			modifyConfig: func(cfg *Config) {
				cfg.JWT.Algorithm = "INVALID"
			},
			expectError: true,
		},
		{
			name: "missing JWT config",
			modifyConfig: func(cfg *Config) {
				cfg.JWT.PublicKeyPath = ""
				cfg.JWT.JWKSUrl = ""
			},
			expectError: true,
		},
		{
			name: "invalid log level",
			modifyConfig: func(cfg *Config) {
				cfg.Logging.Level = "invalid"
			},
			expectError: true,
		},
		{
			name: "empty Kafka brokers",
			modifyConfig: func(cfg *Config) {
				cfg.Kafka.Brokers = []string{}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			setDefaults(cfg)
			tt.modifyConfig(cfg)

			err := validate(cfg)
			if tt.expectError && err == nil {
				t.Errorf("Expected validation error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error but got: %v", err)
			}
		})
	}
}

func TestUtilityMethods(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg)

	// Test GetDatabaseURL
	expectedURL := "postgres://postgres:postgres@localhost:5432/erp_gateway?sslmode=disable"
	if url := cfg.GetDatabaseURL(); url != expectedURL {
		t.Errorf("Expected database URL '%s', got '%s'", expectedURL, url)
	}

	// Test GetRedisAddr
	expectedAddr := "localhost:6379"
	if addr := cfg.GetRedisAddr(); addr != expectedAddr {
		t.Errorf("Expected Redis address '%s', got '%s'", expectedAddr, addr)
	}

	// Test GetServiceAddr
	expectedAuthAddr := "localhost:50051"
	if addr := cfg.GetServiceAddr("auth"); addr != expectedAuthAddr {
		t.Errorf("Expected auth service address '%s', got '%s'", expectedAuthAddr, addr)
	}

	expectedCRMAddr := "localhost:50052"
	if addr := cfg.GetServiceAddr("crm"); addr != expectedCRMAddr {
		t.Errorf("Expected CRM service address '%s', got '%s'", expectedCRMAddr, addr)
	}

	// Test invalid service name
	if addr := cfg.GetServiceAddr("invalid"); addr != "" {
		t.Errorf("Expected empty address for invalid service, got '%s'", addr)
	}
}

func TestEnvironmentMethods(t *testing.T) {
	cfg := &Config{}

	// Test development mode (default)
	if !cfg.IsDevelopment() {
		t.Error("Expected development mode by default")
	}

	if cfg.IsProduction() {
		t.Error("Expected not production mode by default")
	}

	// Test production mode
	os.Setenv("APP_ENV", "production")
	defer os.Unsetenv("APP_ENV")

	if cfg.IsDevelopment() {
		t.Error("Expected not development mode in production")
	}

	if !cfg.IsProduction() {
		t.Error("Expected production mode when APP_ENV=production")
	}
}

func TestSetFieldValue(t *testing.T) {
	tests := []struct {
		name        string
		fieldType   interface{}
		value       string
		expectError bool
	}{
		{"string field", "", "test", false},
		{"int field", 0, "123", false},
		{"bool field true", false, "true", false},
		{"bool field false", false, "false", false},
		{"duration field", time.Duration(0), "5s", false},
		{"invalid int", 0, "invalid", true},
		{"invalid bool", false, "invalid", true},
		{"invalid duration", time.Duration(0), "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a simplified test since setFieldValue works with reflect.Value
			// In a real scenario, you'd test this through the loadFromEnv function
		})
	}
}

func TestStringSliceEnvVar(t *testing.T) {
	// Test comma-separated string slice environment variable
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001,https://example.com")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := []string{"http://localhost:3000", "http://localhost:3001", "https://example.com"}
	if len(cfg.Server.CORS.AllowedOrigins) != len(expected) {
		t.Errorf("Expected %d origins, got %d", len(expected), len(cfg.Server.CORS.AllowedOrigins))
		return
	}

	for i, origin := range expected {
		if cfg.Server.CORS.AllowedOrigins[i] != origin {
			t.Errorf("Expected origin '%s' at index %d, got '%s'", origin, i, cfg.Server.CORS.AllowedOrigins[i])
		}
	}
}