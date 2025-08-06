package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"erp-api-gateway/internal/cache"
)

// CacheWarmingService handles preloading frequently accessed data
type CacheWarmingService struct {
	cache      *cache.CacheManager
	userRepo   UserRepository
	configRepo ConfigRepository
	mu         sync.RWMutex
	running    bool
}

// UserRepository interface for user data access
type UserRepository interface {
	GetActiveUsers(limit int) ([]User, error)
	GetUserProfile(userID string) (*User, error)
	GetUserPermissions(userID string) ([]Permission, error)
}

// ConfigRepository interface for configuration data access
type ConfigRepository interface {
	GetSystemConfig() (*SystemConfig, error)
	GetFeatureFlags() (map[string]bool, error)
}

// User represents user data
type User struct {
	ID          string    `json:"id"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	Email       string    `json:"email"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// Permission represents user permissions
type Permission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// SystemConfig represents system configuration
type SystemConfig struct {
	APIVersion     string            `json:"api_version"`
	Features       map[string]bool   `json:"features"`
	Limits         map[string]int    `json:"limits"`
	LastModified   time.Time         `json:"last_modified"`
	Version        string            `json:"version"`
}

// NewCacheWarmingService creates a new cache warming service
func NewCacheWarmingService(
	cacheManager *cache.CacheManager,
	userRepo UserRepository,
	configRepo ConfigRepository,
) *CacheWarmingService {
	return &CacheWarmingService{
		cache:      cacheManager,
		userRepo:   userRepo,
		configRepo: configRepo,
	}
}

// Start begins the cache warming process
func (cws *CacheWarmingService) Start(ctx context.Context) error {
	cws.mu.Lock()
	if cws.running {
		cws.mu.Unlock()
		return fmt.Errorf("cache warming service is already running")
	}
	cws.running = true
	cws.mu.Unlock()

	log.Println("Starting cache warming service...")

	// Initial warm-up
	if err := cws.warmupInitialData(); err != nil {
		log.Printf("Initial cache warming failed: %v", err)
	}

	// Start periodic warming
	go cws.periodicWarming(ctx)

	return nil
}

// Stop stops the cache warming service
func (cws *CacheWarmingService) Stop() {
	cws.mu.Lock()
	cws.running = false
	cws.mu.Unlock()
	log.Println("Cache warming service stopped")
}

// warmupInitialData preloads critical data on startup
func (cws *CacheWarmingService) warmupInitialData() error {
	log.Println("Starting initial cache warming...")

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Warm system config
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cws.warmSystemConfig(); err != nil {
			errChan <- fmt.Errorf("system config warming failed: %w", err)
		}
	}()

	// Warm active user profiles
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cws.warmActiveUserProfiles(); err != nil {
			errChan <- fmt.Errorf("user profiles warming failed: %w", err)
		}
	}()

	// Warm user permissions
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cws.warmUserPermissions(); err != nil {
			errChan <- fmt.Errorf("user permissions warming failed: %w", err)
		}
	}()

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		log.Printf("Cache warming completed with %d errors", len(errors))
		for _, err := range errors {
			log.Printf("Warming error: %v", err)
		}
		return errors[0] // Return first error
	}

	log.Println("Initial cache warming completed successfully")
	return nil
}

// periodicWarming runs periodic cache refresh
func (cws *CacheWarmingService) periodicWarming(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute) // Refresh every 15 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cws.mu.RLock()
			if !cws.running {
				cws.mu.RUnlock()
				return
			}
			cws.mu.RUnlock()

			log.Println("Running periodic cache warming...")
			if err := cws.warmupInitialData(); err != nil {
				log.Printf("Periodic cache warming failed: %v", err)
			}
		}
	}
}

// warmSystemConfig caches system configuration
func (cws *CacheWarmingService) warmSystemConfig() error {
	config, err := cws.configRepo.GetSystemConfig()
	if err != nil {
		return err
	}

	// Cache for 1 hour
	return cws.cache.SetWithVersion(
		cache.ConfigCacheKey(),
		config,
		time.Hour,
		fmt.Sprintf("v%d", config.LastModified.Unix()),
	)
}

// warmActiveUserProfiles caches profiles of recently active users
func (cws *CacheWarmingService) warmActiveUserProfiles() error {
	users, err := cws.userRepo.GetActiveUsers(100) // Top 100 active users
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent operations

	for _, user := range users {
		wg.Add(1)
		go func(u User) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Cache user profile for 15 minutes
			cacheKey := cache.UserCacheKey(u.ID)
			if err := cws.cache.Set(cacheKey, u, 15*time.Minute); err != nil {
				log.Printf("Failed to cache user profile %s: %v", u.ID, err)
			}
		}(user)
	}

	wg.Wait()
	log.Printf("Warmed %d user profiles", len(users))
	return nil
}

// warmUserPermissions caches user permissions
func (cws *CacheWarmingService) warmUserPermissions() error {
	users, err := cws.userRepo.GetActiveUsers(100)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, user := range users {
		wg.Add(1)
		go func(u User) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			permissions, err := cws.userRepo.GetUserPermissions(u.ID)
			if err != nil {
				log.Printf("Failed to get permissions for user %s: %v", u.ID, err)
				return
			}

			// Cache permissions for 30 minutes
			cacheKey := cache.UserPermissionsCacheKey(u.ID)
			if err := cws.cache.Set(cacheKey, permissions, 30*time.Minute); err != nil {
				log.Printf("Failed to cache permissions for user %s: %v", u.ID, err)
			}
		}(user)
	}

	wg.Wait()
	log.Printf("Warmed permissions for %d users", len(users))
	return nil
}

// WarmUserData preloads data for a specific user (called on login)
func (cws *CacheWarmingService) WarmUserData(userID string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Warm user profile
	wg.Add(1)
	go func() {
		defer wg.Done()
		user, err := cws.userRepo.GetUserProfile(userID)
		if err != nil {
			errChan <- err
			return
		}

		cacheKey := cache.UserCacheKey(userID)
		if err := cws.cache.Set(cacheKey, user, 15*time.Minute); err != nil {
			errChan <- err
		}
	}()

	// Warm user permissions
	wg.Add(1)
	go func() {
		defer wg.Done()
		permissions, err := cws.userRepo.GetUserPermissions(userID)
		if err != nil {
			errChan <- err
			return
		}

		cacheKey := cache.UserPermissionsCacheKey(userID)
		if err := cws.cache.Set(cacheKey, permissions, 30*time.Minute); err != nil {
			errChan <- err
		}
	}()

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// InvalidateUserData removes cached data for a user
func (cws *CacheWarmingService) InvalidateUserData(userID string) error {
	keys := []string{
		cache.UserCacheKey(userID),
		cache.UserPermissionsCacheKey(userID),
		cache.DashboardMetricsCacheKey(userID),
	}

	for _, key := range keys {
		if err := cws.cache.Delete(key); err != nil {
			log.Printf("Failed to invalidate cache key %s: %v", key, err)
		}
	}

	return nil
}

// GetCacheStats returns cache warming statistics
func (cws *CacheWarmingService) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"running":     cws.running,
		"last_run":    time.Now().Format(time.RFC3339),
		"status":      "healthy",
	}
}