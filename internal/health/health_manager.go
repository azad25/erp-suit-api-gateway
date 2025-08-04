package health

import (
	"context"
	"sync"
	"time"

	"erp-api-gateway/internal/interfaces"
)

// HealthStatus represents the health status of a service
type HealthStatus struct {
	Status    string    `json:"status"`
	LastCheck time.Time `json:"last_check"`
	Error     string    `json:"error,omitempty"`
	Latency   int64     `json:"latency_ms,omitempty"`
}

// HealthManager manages health checks with caching and optimization
type HealthManager struct {
	mu           sync.RWMutex
	statuses     map[string]*HealthStatus
	checkers     map[string]HealthChecker
	logger       interfaces.SimpleLogger
	
	// Configuration
	cacheTimeout    time.Duration
	checkInterval   time.Duration
	maxConcurrent   int
	
	// Control
	stopChan        chan struct{}
	running         bool
}

// HealthChecker interface for different service health checks
type HealthChecker interface {
	Check(ctx context.Context) error
	Name() string
}

// NewHealthManager creates a new optimized health manager
func NewHealthManager(logger interfaces.SimpleLogger) *HealthManager {
	return &HealthManager{
		statuses:      make(map[string]*HealthStatus),
		checkers:      make(map[string]HealthChecker),
		logger:        logger,
		cacheTimeout:  30 * time.Second,  // Cache health status for 30 seconds
		checkInterval: 60 * time.Second,  // Check every 60 seconds (reduced from 30)
		maxConcurrent: 3,                 // Max 3 concurrent health checks
		stopChan:      make(chan struct{}),
	}
}

// RegisterChecker registers a health checker
func (hm *HealthManager) RegisterChecker(checker HealthChecker) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	name := checker.Name()
	hm.checkers[name] = checker
	hm.statuses[name] = &HealthStatus{
		Status:    "unknown",
		LastCheck: time.Time{},
	}
}

// Start begins the background health checking
func (hm *HealthManager) Start() {
	hm.mu.Lock()
	if hm.running {
		hm.mu.Unlock()
		return
	}
	hm.running = true
	hm.mu.Unlock()

	go hm.healthCheckLoop()
	
	hm.logger.LogInfo(context.Background(), "Health manager started", map[string]interface{}{
		"cache_timeout":  hm.cacheTimeout,
		"check_interval": hm.checkInterval,
		"checkers":       len(hm.checkers),
	})
}

// Stop stops the health checking
func (hm *HealthManager) Stop() {
	hm.mu.Lock()
	if !hm.running {
		hm.mu.Unlock()
		return
	}
	hm.running = false
	hm.mu.Unlock()

	close(hm.stopChan)
	hm.logger.LogInfo(context.Background(), "Health manager stopped", nil)
}

// GetStatus returns cached health status (fast, non-blocking)
func (hm *HealthManager) GetStatus(serviceName string) *HealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	status, exists := hm.statuses[serviceName]
	if !exists {
		return &HealthStatus{
			Status:    "unknown",
			LastCheck: time.Time{},
			Error:     "service not registered",
		}
	}
	
	// Return cached status if still valid
	if time.Since(status.LastCheck) < hm.cacheTimeout {
		return status
	}
	
	// Return stale status but mark it as stale
	staleStatus := *status
	staleStatus.Status = "stale"
	return &staleStatus
}

// GetAllStatuses returns all cached health statuses
func (hm *HealthManager) GetAllStatuses() map[string]*HealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	result := make(map[string]*HealthStatus)
	for name, status := range hm.statuses {
		statusCopy := *status
		
		// Mark as stale if cache expired
		if time.Since(status.LastCheck) >= hm.cacheTimeout {
			statusCopy.Status = "stale"
		}
		
		result[name] = &statusCopy
	}
	
	return result
}

// IsHealthy returns overall health status (fast check)
func (hm *HealthManager) IsHealthy() bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	for _, status := range hm.statuses {
		// Skip if never checked or too old
		if status.LastCheck.IsZero() || time.Since(status.LastCheck) > hm.cacheTimeout*2 {
			continue
		}
		
		if status.Status != "healthy" {
			return false
		}
	}
	
	return true
}

// ForceCheck forces an immediate health check for a specific service
func (hm *HealthManager) ForceCheck(serviceName string) *HealthStatus {
	hm.mu.RLock()
	checker, exists := hm.checkers[serviceName]
	hm.mu.RUnlock()
	
	if !exists {
		return &HealthStatus{
			Status: "unknown",
			Error:  "service not registered",
		}
	}
	
	return hm.checkService(checker)
}

// healthCheckLoop runs the background health checking
func (hm *HealthManager) healthCheckLoop() {
	ticker := time.NewTicker(hm.checkInterval)
	defer ticker.Stop()
	
	// Initial check
	hm.performHealthChecks()
	
	for {
		select {
		case <-ticker.C:
			hm.performHealthChecks()
		case <-hm.stopChan:
			return
		}
	}
}

// performHealthChecks performs health checks with concurrency control
func (hm *HealthManager) performHealthChecks() {
	hm.mu.RLock()
	checkers := make([]HealthChecker, 0, len(hm.checkers))
	for _, checker := range hm.checkers {
		checkers = append(checkers, checker)
	}
	hm.mu.RUnlock()
	
	if len(checkers) == 0 {
		return
	}
	
	// Use semaphore to limit concurrent checks
	semaphore := make(chan struct{}, hm.maxConcurrent)
	var wg sync.WaitGroup
	
	for _, checker := range checkers {
		wg.Add(1)
		go func(c HealthChecker) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			status := hm.checkService(c)
			
			// Update status
			hm.mu.Lock()
			hm.statuses[c.Name()] = status
			hm.mu.Unlock()
		}(checker)
	}
	
	wg.Wait()
	
	hm.logger.LogInfo(context.Background(), "Health checks completed", map[string]interface{}{
		"services_checked": len(checkers),
		"duration":         hm.checkInterval,
	})
}

// checkService performs a single health check
func (hm *HealthManager) checkService(checker HealthChecker) *HealthStatus {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := checker.Check(ctx)
	latency := time.Since(start).Milliseconds()
	
	status := &HealthStatus{
		LastCheck: time.Now(),
		Latency:   latency,
	}
	
	if err != nil {
		status.Status = "unhealthy"
		status.Error = err.Error()
		
		hm.logger.LogWarning(context.Background(), "Health check failed", map[string]interface{}{
			"service": checker.Name(),
			"error":   err.Error(),
			"latency": latency,
		})
	} else {
		status.Status = "healthy"
		
		hm.logger.LogInfo(context.Background(), "Health check passed", map[string]interface{}{
			"service": checker.Name(),
			"latency": latency,
		})
	}
	
	return status
}