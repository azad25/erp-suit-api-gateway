package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server     ServerConfig         `yaml:"server"`
	Database   DatabaseConfig       `yaml:"database"`
	Redis      RedisConfig          `yaml:"redis"`
	Kafka      KafkaConfig          `yaml:"kafka"`
	GRPC       GRPCConfig           `yaml:"grpc"`
	JWT        JWTConfig            `yaml:"jwt"`
	Logging    LoggingConfig        `yaml:"logging"`
	WebSocket  WebSocketConfig      `yaml:"websocket"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
}

// ServerConfig represents HTTP server configuration
type ServerConfig struct {
	Port            int           `yaml:"port" json:"port" env:"SERVER_PORT" validate:"min=1,max=65535"`
	Host            string        `yaml:"host" json:"host" env:"SERVER_HOST" validate:"required"`
	ReadTimeout     time.Duration `yaml:"read_timeout" json:"read_timeout" env:"SERVER_READ_TIMEOUT"`
	WriteTimeout    time.Duration `yaml:"write_timeout" json:"write_timeout" env:"SERVER_WRITE_TIMEOUT"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout" env:"SERVER_SHUTDOWN_TIMEOUT"`
	CORS            CORSConfig    `yaml:"cors" json:"cors"`
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed_origins" json:"allowed_origins" env:"CORS_ALLOWED_ORIGINS"`
	AllowedMethods   []string `yaml:"allowed_methods" json:"allowed_methods" env:"CORS_ALLOWED_METHODS"`
	AllowedHeaders   []string `yaml:"allowed_headers" json:"allowed_headers" env:"CORS_ALLOWED_HEADERS"`
	AllowCredentials bool     `yaml:"allow_credentials" json:"allow_credentials" env:"CORS_ALLOW_CREDENTIALS"`
	MaxAge           int      `yaml:"max_age" json:"max_age" env:"CORS_MAX_AGE" validate:"min=0"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Host     string `yaml:"host" json:"host" env:"DB_HOST" validate:"required"`
	Port     int    `yaml:"port" json:"port" env:"DB_PORT" validate:"min=1,max=65535"`
	Name     string `yaml:"name" json:"name" env:"DB_NAME" validate:"required"`
	User     string `yaml:"user" json:"user" env:"DB_USER" validate:"required"`
	Password string `yaml:"password" json:"password" env:"DB_PASSWORD" validate:"required"`
	SSLMode  string `yaml:"ssl_mode" json:"ssl_mode" env:"DB_SSL_MODE" validate:"oneof=disable require verify-ca verify-full"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Host         string        `yaml:"host" json:"host" env:"REDIS_HOST" validate:"required"`
	Port         int           `yaml:"port" json:"port" env:"REDIS_PORT" validate:"min=1,max=65535"`
	Password     string        `yaml:"password" json:"password" env:"REDIS_PASSWORD"`
	DB           int           `yaml:"db" json:"db" env:"REDIS_DB" validate:"min=0,max=15"`
	PoolSize     int           `yaml:"pool_size" json:"pool_size" env:"REDIS_POOL_SIZE" validate:"min=1"`
	MinIdleConns int           `yaml:"min_idle_conns" json:"min_idle_conns" env:"REDIS_MIN_IDLE_CONNS" validate:"min=0"`
	DialTimeout  time.Duration `yaml:"dial_timeout" json:"dial_timeout" env:"REDIS_DIAL_TIMEOUT"`
	ReadTimeout  time.Duration `yaml:"read_timeout" json:"read_timeout" env:"REDIS_READ_TIMEOUT"`
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout" env:"REDIS_WRITE_TIMEOUT"`
}

// KafkaConfig represents Kafka configuration
type KafkaConfig struct {
	Brokers       []string      `yaml:"brokers" json:"brokers" env:"KAFKA_BROKERS" validate:"required,min=1"`
	ClientID      string        `yaml:"client_id" json:"client_id" env:"KAFKA_CLIENT_ID" validate:"required"`
	RetryMax      int           `yaml:"retry_max" json:"retry_max" env:"KAFKA_RETRY_MAX" validate:"min=0"`
	RetryBackoff  time.Duration `yaml:"retry_backoff" json:"retry_backoff" env:"KAFKA_RETRY_BACKOFF"`
	FlushMessages int           `yaml:"flush_messages" json:"flush_messages" env:"KAFKA_FLUSH_MESSAGES" validate:"min=1"`
	FlushBytes    int           `yaml:"flush_bytes" json:"flush_bytes" env:"KAFKA_FLUSH_BYTES" validate:"min=1"`
	FlushTimeout  time.Duration `yaml:"flush_timeout" json:"flush_timeout" env:"KAFKA_FLUSH_TIMEOUT"`
}

// GRPCConfig represents gRPC services configuration
type GRPCConfig struct {
	AuthService           ServiceConfig `yaml:"auth_service"`
	CRMService            ServiceConfig `yaml:"crm_service"`
	HRMService            ServiceConfig `yaml:"hrm_service"`
	FinanceService        ServiceConfig `yaml:"finance_service"`
	AuthServiceAddress    string        `yaml:"auth_service_address"`
	CRMServiceAddress     string        `yaml:"crm_service_address"`
	HRMServiceAddress     string        `yaml:"hrm_service_address"`
	FinanceServiceAddress string        `yaml:"finance_service_address"`
	ConsulAddress         string        `yaml:"consul_address"`
	MaxRetries            int           `yaml:"max_retries"`
	RetryInitialInterval  time.Duration `yaml:"retry_initial_interval"`
	RetryMaxInterval      time.Duration `yaml:"retry_max_interval"`
	RetryMultiplier       float64       `yaml:"retry_multiplier"`
	RetryRandomFactor     float64       `yaml:"retry_random_factor"`
	MaxConnections        int           `yaml:"max_connections"`
	ConnectTimeout        time.Duration `yaml:"connect_timeout"`
	MaxIdleTime           time.Duration `yaml:"max_idle_time"`
	MaxConnectionAge      time.Duration `yaml:"max_connection_age"`
	KeepAliveTime         time.Duration `yaml:"keep_alive_time"`
	KeepAliveTimeout      time.Duration `yaml:"keep_alive_timeout"`
	EnableHealthCheck     bool          `yaml:"enable_health_check"`
	HealthCheckInterval   time.Duration `yaml:"health_check_interval"`
	CircuitBreakerMaxRequests uint32    `yaml:"circuit_breaker_max_requests"`
	CircuitBreakerInterval    time.Duration `yaml:"circuit_breaker_interval"`
	CircuitBreakerTimeout     time.Duration `yaml:"circuit_breaker_timeout"`
}

// ServiceConfig represents individual service configuration
type ServiceConfig struct {
	Host            string                  `yaml:"host" json:"host" env:"HOST" validate:"required"`
	Port            int                     `yaml:"port" json:"port" env:"PORT" validate:"min=1,max=65535"`
	Timeout         time.Duration           `yaml:"timeout" json:"timeout" env:"TIMEOUT"`
	MaxRetries      int                     `yaml:"max_retries" json:"max_retries" env:"MAX_RETRIES" validate:"min=0"`
	RetryBackoff    time.Duration           `yaml:"retry_backoff" json:"retry_backoff" env:"RETRY_BACKOFF"`
	CircuitBreaker  CircuitBreakerSettings  `yaml:"circuit_breaker" json:"circuit_breaker"`
}



// JWTConfig represents JWT configuration
type JWTConfig struct {
	PublicKeyPath string        `yaml:"public_key_path" json:"public_key_path" env:"JWT_PUBLIC_KEY_PATH"`
	JWKSUrl       string        `yaml:"jwks_url" json:"jwks_url" env:"JWT_JWKS_URL"`
	CacheTTL      time.Duration `yaml:"cache_ttl" json:"cache_ttl" env:"JWT_CACHE_TTL"`
	Algorithm     string        `yaml:"algorithm" json:"algorithm" env:"JWT_ALGORITHM" validate:"oneof=RS256 ES256 HS256"`
	Issuer        string        `yaml:"issuer" json:"issuer" env:"JWT_ISSUER"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level           string            `yaml:"level" json:"level" env:"LOG_LEVEL" validate:"oneof=debug info warn error fatal"`
	Format          string            `yaml:"format" json:"format" env:"LOG_FORMAT" validate:"oneof=json text"`
	Output          string            `yaml:"output" json:"output" env:"LOG_OUTPUT" validate:"oneof=stdout stderr file"`
	Elasticsearch   ElasticsearchConfig `yaml:"elasticsearch" json:"elasticsearch"`
	BufferSize      int               `yaml:"buffer_size" json:"buffer_size" env:"LOG_BUFFER_SIZE" validate:"min=1"`
	FlushInterval   time.Duration     `yaml:"flush_interval" json:"flush_interval" env:"LOG_FLUSH_INTERVAL"`
}

// ElasticsearchConfig represents Elasticsearch configuration
type ElasticsearchConfig struct {
	URLs      []string `yaml:"urls" json:"urls" env:"ELASTICSEARCH_URLS" validate:"required,min=1"`
	Username  string   `yaml:"username" json:"username" env:"ELASTICSEARCH_USERNAME"`
	Password  string   `yaml:"password" json:"password" env:"ELASTICSEARCH_PASSWORD"`
	IndexName string   `yaml:"index_name" json:"index_name" env:"ELASTICSEARCH_INDEX_NAME" validate:"required"`
}

// WebSocketConfig represents WebSocket configuration
type WebSocketConfig struct {
	ReadBufferSize       int           `yaml:"read_buffer_size" json:"read_buffer_size" env:"WS_READ_BUFFER_SIZE" validate:"min=1024"`
	WriteBufferSize      int           `yaml:"write_buffer_size" json:"write_buffer_size" env:"WS_WRITE_BUFFER_SIZE" validate:"min=1024"`
	HandshakeTimeout     time.Duration `yaml:"handshake_timeout" json:"handshake_timeout" env:"WS_HANDSHAKE_TIMEOUT"`
	ReadTimeout          time.Duration `yaml:"read_timeout" json:"read_timeout" env:"WS_READ_TIMEOUT"`
	WriteTimeout         time.Duration `yaml:"write_timeout" json:"write_timeout" env:"WS_WRITE_TIMEOUT"`
	PongTimeout          time.Duration `yaml:"pong_timeout" json:"pong_timeout" env:"WS_PONG_TIMEOUT"`
	PingPeriod           time.Duration `yaml:"ping_period" json:"ping_period" env:"WS_PING_PERIOD"`
	MaxMessageSize       int64         `yaml:"max_message_size" json:"max_message_size" env:"WS_MAX_MESSAGE_SIZE" validate:"min=1024"`
	MaxConnections       int           `yaml:"max_connections" json:"max_connections" env:"WS_MAX_CONNECTIONS" validate:"min=1"`
	AllowedOrigins       []string      `yaml:"allowed_origins" json:"allowed_origins" env:"WS_ALLOWED_ORIGINS"`
	EnableCompression    bool          `yaml:"enable_compression" json:"enable_compression" env:"WS_ENABLE_COMPRESSION"`
	CompressionLevel     int           `yaml:"compression_level" json:"compression_level" env:"WS_COMPRESSION_LEVEL" validate:"min=-1,max=9"`
}


// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	cfg := &Config{}
	
	// Set defaults
	setDefaults(cfg)
	
	// Load from config file if exists
	if configFile := os.Getenv("CONFIG_FILE"); configFile != "" {
		if err := loadFromFile(cfg, configFile); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}
	
	// Override with environment variables
	if err := loadFromEnv(cfg); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}
	
	// Validate configuration
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return cfg, nil
}

// LoadFromPath loads configuration from a specific file path
func LoadFromPath(configPath string) (*Config, error) {
	cfg := &Config{}
	
	// Set defaults
	setDefaults(cfg)
	
	// Load from specified config file
	if err := loadFromFile(cfg, configPath); err != nil {
		return nil, fmt.Errorf("failed to load config file %s: %w", configPath, err)
	}
	
	// Override with environment variables
	if err := loadFromEnv(cfg); err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}
	
	// Validate configuration
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(cfg *Config) {
	// Server defaults
	cfg.Server.Port = 8080
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.ReadTimeout = 30 * time.Second
	cfg.Server.WriteTimeout = 30 * time.Second
	cfg.Server.ShutdownTimeout = 10 * time.Second
	
	// CORS defaults
	cfg.Server.CORS.AllowedOrigins = []string{"http://localhost:3000", "http://localhost:3001"}
	cfg.Server.CORS.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
	cfg.Server.CORS.AllowedHeaders = []string{"Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin"}
	cfg.Server.CORS.AllowCredentials = true
	cfg.Server.CORS.MaxAge = 86400
	
	// Database defaults
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.Name = "erp_gateway"
	cfg.Database.User = "postgres"
	cfg.Database.Password = "postgres"
	cfg.Database.SSLMode = "disable"
	
	// Redis defaults
	cfg.Redis.Host = "localhost"
	cfg.Redis.Port = 6379
	cfg.Redis.DB = 0
	cfg.Redis.PoolSize = 10
	cfg.Redis.MinIdleConns = 5
	cfg.Redis.DialTimeout = 5 * time.Second
	cfg.Redis.ReadTimeout = 3 * time.Second
	cfg.Redis.WriteTimeout = 3 * time.Second
	
	// Kafka defaults
	cfg.Kafka.Brokers = []string{"localhost:9092"}
	cfg.Kafka.ClientID = "erp-api-gateway"
	cfg.Kafka.RetryMax = 3
	cfg.Kafka.RetryBackoff = 100 * time.Millisecond
	cfg.Kafka.FlushMessages = 100
	cfg.Kafka.FlushBytes = 1024 * 1024
	cfg.Kafka.FlushTimeout = 1 * time.Second
	
	// gRPC service defaults
	setServiceDefaults(&cfg.GRPC.AuthService, "localhost", 50051)
	setServiceDefaults(&cfg.GRPC.CRMService, "localhost", 50052)
	setServiceDefaults(&cfg.GRPC.HRMService, "localhost", 50053)
	setServiceDefaults(&cfg.GRPC.FinanceService, "localhost", 50054)
	
	// JWT defaults
	cfg.JWT.Algorithm = "RS256"
	cfg.JWT.CacheTTL = 1 * time.Hour
	cfg.JWT.Issuer = "erp-auth-service"
	cfg.JWT.JWKSUrl = "http://localhost:8081/.well-known/jwks.json"
	
	// Logging defaults
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"
	cfg.Logging.Output = "stdout"
	cfg.Logging.BufferSize = 1000
	cfg.Logging.FlushInterval = 5 * time.Second
	cfg.Logging.Elasticsearch.URLs = []string{"http://localhost:9200"}
	cfg.Logging.Elasticsearch.IndexName = "erp-api-gateway-logs"
	
	// WebSocket defaults
	cfg.WebSocket.ReadBufferSize = 4096
	cfg.WebSocket.WriteBufferSize = 4096
	cfg.WebSocket.HandshakeTimeout = 10 * time.Second
	cfg.WebSocket.ReadTimeout = 60 * time.Second
	cfg.WebSocket.WriteTimeout = 10 * time.Second
	cfg.WebSocket.PongTimeout = 60 * time.Second
	cfg.WebSocket.PingPeriod = 54 * time.Second // Must be less than PongTimeout
	cfg.WebSocket.MaxMessageSize = 1024 * 1024  // 1MB
	cfg.WebSocket.MaxConnections = 10000
	cfg.WebSocket.AllowedOrigins = []string{"http://localhost:3000", "http://localhost:3001"}
	cfg.WebSocket.EnableCompression = true
	cfg.WebSocket.CompressionLevel = 1
}

// setServiceDefaults sets default values for a service configuration
func setServiceDefaults(svc *ServiceConfig, host string, port int) {
	svc.Host = host
	svc.Port = port
	svc.Timeout = 10 * time.Second
	svc.MaxRetries = 3
	svc.RetryBackoff = 100 * time.Millisecond
	svc.CircuitBreaker.MaxRequests = 5
	svc.CircuitBreaker.Timeout = 60 * time.Second
	svc.CircuitBreaker.Interval = 10 * time.Second
	svc.CircuitBreaker.ReadyToTrip = 3
}

// loadFromFile loads configuration from YAML or JSON file
func loadFromFile(cfg *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Determine file format based on extension
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(data, cfg); err != nil {
			if jsonErr := json.Unmarshal(data, cfg); jsonErr != nil {
				return fmt.Errorf("failed to parse config as YAML (%v) or JSON (%v)", err, jsonErr)
			}
		}
	}
	
	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(cfg *Config) error {
	return loadEnvVars(reflect.ValueOf(cfg).Elem(), "")
}

// loadEnvVars recursively loads environment variables into struct fields
func loadEnvVars(v reflect.Value, prefix string) error {
	t := v.Type()
	
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		
		// Skip unexported fields
		if !field.CanSet() {
			continue
		}
		
		// Get environment variable name from tag
		envTag := fieldType.Tag.Get("env")
		if envTag != "" {
			// Use the environment variable directly (no prefix modification)
			envValue := os.Getenv(envTag)
			if envValue != "" {
				// Set field value based on type
				if err := setFieldValue(field, envValue); err != nil {
					return fmt.Errorf("failed to set field %s from env %s: %w", fieldType.Name, envTag, err)
				}
			}
		} else if field.Kind() == reflect.Struct {
			// For nested structs, recurse without prefix changes
			if err := loadEnvVars(field, prefix); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// setFieldValue sets a struct field value from a string
func setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
		
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			// Handle time.Duration
			duration, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}
			field.SetInt(int64(duration))
		} else {
			// Handle regular integers
			intVal, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid integer: %w", err)
			}
			field.SetInt(intVal)
		}
		
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean: %w", err)
		}
		field.SetBool(boolVal)
		
	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.String {
			// Handle string slices (comma-separated values)
			values := strings.Split(value, ",")
			for i, v := range values {
				values[i] = strings.TrimSpace(v)
			}
			field.Set(reflect.ValueOf(values))
		} else {
			return fmt.Errorf("unsupported slice type: %s", field.Type())
		}
		
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}
	
	return nil
}

// validate validates the configuration
func validate(cfg *Config) error {
	// Validate server configuration
	if err := validateServer(&cfg.Server); err != nil {
		return fmt.Errorf("server config validation failed: %w", err)
	}
	
	// Validate database configuration
	if err := validateDatabase(&cfg.Database); err != nil {
		return fmt.Errorf("database config validation failed: %w", err)
	}
	
	// Validate Redis configuration
	if err := validateRedis(&cfg.Redis); err != nil {
		return fmt.Errorf("redis config validation failed: %w", err)
	}
	
	// Validate Kafka configuration
	if err := validateKafka(&cfg.Kafka); err != nil {
		return fmt.Errorf("kafka config validation failed: %w", err)
	}
	
	// Validate gRPC configuration
	if err := validateGRPC(&cfg.GRPC); err != nil {
		return fmt.Errorf("grpc config validation failed: %w", err)
	}
	
	// Validate JWT configuration
	if err := validateJWT(&cfg.JWT); err != nil {
		return fmt.Errorf("jwt config validation failed: %w", err)
	}
	
	// Validate logging configuration
	if err := validateLogging(&cfg.Logging); err != nil {
		return fmt.Errorf("logging config validation failed: %w", err)
	}
	
	// Validate WebSocket configuration
	if err := validateWebSocket(&cfg.WebSocket); err != nil {
		return fmt.Errorf("websocket config validation failed: %w", err)
	}
	
	return nil
}

// validateServer validates server configuration
func validateServer(cfg *ServerConfig) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be between 1 and 65535)", cfg.Port)
	}
	
	if cfg.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	
	if cfg.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}
	
	if cfg.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}
	
	if cfg.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive")
	}
	
	return validateCORS(&cfg.CORS)
}

// validateCORS validates CORS configuration
func validateCORS(cfg *CORSConfig) error {
	if len(cfg.AllowedOrigins) == 0 {
		return fmt.Errorf("allowed origins cannot be empty")
	}
	
	if len(cfg.AllowedMethods) == 0 {
		return fmt.Errorf("allowed methods cannot be empty")
	}
	
	if cfg.MaxAge < 0 {
		return fmt.Errorf("max age cannot be negative")
	}
	
	return nil
}

// validateDatabase validates database configuration
func validateDatabase(cfg *DatabaseConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.Port)
	}
	
	if cfg.Name == "" {
		return fmt.Errorf("database name cannot be empty")
	}
	
	if cfg.User == "" {
		return fmt.Errorf("user cannot be empty")
	}
	
	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	if cfg.SSLMode != "" && !contains(validSSLModes, cfg.SSLMode) {
		return fmt.Errorf("invalid ssl_mode: %s (must be one of: %s)", cfg.SSLMode, strings.Join(validSSLModes, ", "))
	}
	
	return nil
}

// validateRedis validates Redis configuration
func validateRedis(cfg *RedisConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.Port)
	}
	
	if cfg.DB < 0 || cfg.DB > 15 {
		return fmt.Errorf("invalid database: %d (must be between 0 and 15)", cfg.DB)
	}
	
	if cfg.PoolSize <= 0 {
		return fmt.Errorf("pool size must be positive")
	}
	
	if cfg.MinIdleConns < 0 {
		return fmt.Errorf("min idle connections cannot be negative")
	}
	
	return nil
}

// validateKafka validates Kafka configuration
func validateKafka(cfg *KafkaConfig) error {
	if len(cfg.Brokers) == 0 {
		return fmt.Errorf("brokers cannot be empty")
	}
	
	if cfg.ClientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}
	
	if cfg.RetryMax < 0 {
		return fmt.Errorf("retry max cannot be negative")
	}
	
	if cfg.FlushMessages <= 0 {
		return fmt.Errorf("flush messages must be positive")
	}
	
	if cfg.FlushBytes <= 0 {
		return fmt.Errorf("flush bytes must be positive")
	}
	
	return nil
}

// validateGRPC validates gRPC configuration
func validateGRPC(cfg *GRPCConfig) error {
	if err := validateService("auth_service", &cfg.AuthService); err != nil {
		return err
	}
	
	if err := validateService("crm_service", &cfg.CRMService); err != nil {
		return err
	}
	
	if err := validateService("hrm_service", &cfg.HRMService); err != nil {
		return err
	}
	
	if err := validateService("finance_service", &cfg.FinanceService); err != nil {
		return err
	}
	
	return nil
}

// validateService validates individual service configuration
func validateService(name string, cfg *ServiceConfig) error {
	if cfg.Host == "" {
		return fmt.Errorf("%s host cannot be empty", name)
	}
	
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("%s invalid port: %d", name, cfg.Port)
	}
	
	if cfg.Timeout <= 0 {
		return fmt.Errorf("%s timeout must be positive", name)
	}
	
	if cfg.MaxRetries < 0 {
		return fmt.Errorf("%s max retries cannot be negative", name)
	}
	
	return validateCircuitBreaker(name, &cfg.CircuitBreaker)
}

// validateCircuitBreaker validates circuit breaker configuration
func validateCircuitBreaker(serviceName string, cfg *CircuitBreakerSettings) error {
	if cfg.MaxRequests <= 0 {
		return fmt.Errorf("%s circuit breaker max requests must be positive", serviceName)
	}
	
	if cfg.Timeout <= 0 {
		return fmt.Errorf("%s circuit breaker timeout must be positive", serviceName)
	}
	
	if cfg.Interval <= 0 {
		return fmt.Errorf("%s circuit breaker interval must be positive", serviceName)
	}
	
	if cfg.ReadyToTrip <= 0 {
		return fmt.Errorf("%s circuit breaker ready to trip must be positive", serviceName)
	}
	
	return nil
}

// validateJWT validates JWT configuration
func validateJWT(cfg *JWTConfig) error {
	if cfg.PublicKeyPath == "" && cfg.JWKSUrl == "" {
		return fmt.Errorf("either public key path or JWKS URL must be provided")
	}
	
	validAlgorithms := []string{"RS256", "ES256", "HS256"}
	if cfg.Algorithm != "" && !contains(validAlgorithms, cfg.Algorithm) {
		return fmt.Errorf("invalid algorithm: %s (must be one of: %s)", cfg.Algorithm, strings.Join(validAlgorithms, ", "))
	}
	
	if cfg.CacheTTL <= 0 {
		return fmt.Errorf("cache TTL must be positive")
	}
	
	return nil
}

// validateLogging validates logging configuration
func validateLogging(cfg *LoggingConfig) error {
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	if cfg.Level != "" && !contains(validLevels, cfg.Level) {
		return fmt.Errorf("invalid log level: %s (must be one of: %s)", cfg.Level, strings.Join(validLevels, ", "))
	}
	
	validFormats := []string{"json", "text"}
	if cfg.Format != "" && !contains(validFormats, cfg.Format) {
		return fmt.Errorf("invalid log format: %s (must be one of: %s)", cfg.Format, strings.Join(validFormats, ", "))
	}
	
	validOutputs := []string{"stdout", "stderr", "file"}
	if cfg.Output != "" && !contains(validOutputs, cfg.Output) {
		return fmt.Errorf("invalid log output: %s (must be one of: %s)", cfg.Output, strings.Join(validOutputs, ", "))
	}
	
	if cfg.BufferSize <= 0 {
		return fmt.Errorf("buffer size must be positive")
	}
	
	if cfg.FlushInterval <= 0 {
		return fmt.Errorf("flush interval must be positive")
	}
	
	return validateElasticsearch(&cfg.Elasticsearch)
}

// validateElasticsearch validates Elasticsearch configuration
func validateElasticsearch(cfg *ElasticsearchConfig) error {
	if len(cfg.URLs) == 0 {
		return fmt.Errorf("elasticsearch URLs cannot be empty")
	}
	
	if cfg.IndexName == "" {
		return fmt.Errorf("elasticsearch index name cannot be empty")
	}
	
	return nil
}

// validateWebSocket validates WebSocket configuration
func validateWebSocket(cfg *WebSocketConfig) error {
	if cfg.ReadBufferSize < 1024 {
		return fmt.Errorf("read buffer size must be at least 1024 bytes")
	}
	
	if cfg.WriteBufferSize < 1024 {
		return fmt.Errorf("write buffer size must be at least 1024 bytes")
	}
	
	if cfg.HandshakeTimeout <= 0 {
		return fmt.Errorf("handshake timeout must be positive")
	}
	
	if cfg.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}
	
	if cfg.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}
	
	if cfg.PongTimeout <= 0 {
		return fmt.Errorf("pong timeout must be positive")
	}
	
	if cfg.PingPeriod <= 0 {
		return fmt.Errorf("ping period must be positive")
	}
	
	if cfg.PingPeriod >= cfg.PongTimeout {
		return fmt.Errorf("ping period must be less than pong timeout")
	}
	
	if cfg.MaxMessageSize < 1024 {
		return fmt.Errorf("max message size must be at least 1024 bytes")
	}
	
	if cfg.MaxConnections <= 0 {
		return fmt.Errorf("max connections must be positive")
	}
	
	if len(cfg.AllowedOrigins) == 0 {
		return fmt.Errorf("allowed origins cannot be empty")
	}
	
	if cfg.CompressionLevel < -1 || cfg.CompressionLevel > 9 {
		return fmt.Errorf("compression level must be between -1 and 9")
	}
	
	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetDatabaseURL returns a formatted database connection URL
func (cfg *Config) GetDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)
}

// GetRedisAddr returns the Redis address in host:port format
func (cfg *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
}

// GetServiceAddr returns the address for a specific gRPC service
func (cfg *Config) GetServiceAddr(serviceName string) string {
	var svc *ServiceConfig
	switch strings.ToLower(serviceName) {
	case "auth":
		svc = &cfg.GRPC.AuthService
	case "crm":
		svc = &cfg.GRPC.CRMService
	case "hrm":
		svc = &cfg.GRPC.HRMService
	case "finance":
		svc = &cfg.GRPC.FinanceService
	default:
		return ""
	}
	return fmt.Sprintf("%s:%d", svc.Host, svc.Port)
}

// IsProduction returns true if the application is running in production mode
func (cfg *Config) IsProduction() bool {
	env := strings.ToLower(os.Getenv("APP_ENV"))
	return env == "production" || env == "prod"
}

// IsDevelopment returns true if the application is running in development mode
func (cfg *Config) IsDevelopment() bool {
	env := strings.ToLower(os.Getenv("APP_ENV"))
	return env == "development" || env == "dev" || env == ""
}

// String returns a string representation of the configuration (with sensitive data masked)
func (cfg *Config) String() string {
	// Create a copy of the config with sensitive data masked
	masked := *cfg
	masked.Database.Password = "***"
	masked.Redis.Password = "***"
	masked.Logging.Elasticsearch.Password = "***"
	
	data, _ := json.MarshalIndent(masked, "", "  ")
	return string(data)
}

// SetServiceAddress sets the address for a specific service
func (c *GRPCConfig) SetServiceAddress(serviceName, address string) {
	switch serviceName {
	case "auth":
		c.AuthServiceAddress = address
	case "crm":
		c.CRMServiceAddress = address
	case "hrm":
		c.HRMServiceAddress = address
	case "finance":
		c.FinanceServiceAddress = address
	}
}