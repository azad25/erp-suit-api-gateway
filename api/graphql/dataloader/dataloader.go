package dataloader

import (
	"context"
	"fmt"
	"sync"
	"time"

	"erp-api-gateway/api/graphql/helpers"
	"erp-api-gateway/api/graphql/model"
	"erp-api-gateway/internal/services/grpc_client"
	authpb "erp-api-gateway/proto"
)

// DataLoader implements the DataLoader pattern to prevent N+1 query problems
type DataLoader struct {
	grpcClient *grpc_client.GRPCClient
	
	// User loaders
	userLoader       *UserLoader
	userRoleLoader   *UserRoleLoader
	userPermLoader   *UserPermissionLoader
	
	// Cache settings
	maxBatchSize int
	wait         time.Duration
}

// NewDataLoader creates a new DataLoader instance
func NewDataLoader(grpcClient *grpc_client.GRPCClient) *DataLoader {
	dl := &DataLoader{
		grpcClient:   grpcClient,
		maxBatchSize: 100,
		wait:         1 * time.Millisecond,
	}
	
	// Initialize loaders
	dl.userLoader = NewUserLoader(dl)
	dl.userRoleLoader = NewUserRoleLoader(dl)
	dl.userPermLoader = NewUserPermissionLoader(dl)
	
	return dl
}

// GetUser loads a user by ID using batching
func (dl *DataLoader) GetUser(ctx context.Context, userID string) (*model.User, error) {
	return dl.userLoader.Load(ctx, userID)
}

// GetUserRoles loads roles for a user using batching
func (dl *DataLoader) GetUserRoles(ctx context.Context, userID string) ([]*model.Role, error) {
	return dl.userRoleLoader.Load(ctx, userID)
}

// GetUserPermissions loads permissions for a user using batching
func (dl *DataLoader) GetUserPermissions(ctx context.Context, userID string) ([]*model.Permission, error) {
	return dl.userPermLoader.Load(ctx, userID)
}

// UserLoader handles batched user loading
type UserLoader struct {
	dataLoader *DataLoader
	cache      map[string]*model.User
	mutex      sync.RWMutex
	batch      []string
	batchMutex sync.Mutex
	timer      *time.Timer
}

// NewUserLoader creates a new UserLoader
func NewUserLoader(dl *DataLoader) *UserLoader {
	return &UserLoader{
		dataLoader: dl,
		cache:      make(map[string]*model.User),
		batch:      make([]string, 0),
	}
}

// Load loads a user by ID with batching
func (ul *UserLoader) Load(ctx context.Context, userID string) (*model.User, error) {
	// Check cache first
	ul.mutex.RLock()
	if user, exists := ul.cache[userID]; exists {
		ul.mutex.RUnlock()
		return user, nil
	}
	ul.mutex.RUnlock()
	
	// Add to batch
	ul.batchMutex.Lock()
	ul.batch = append(ul.batch, userID)
	
	// Start timer if this is the first item in batch
	if len(ul.batch) == 1 {
		ul.timer = time.AfterFunc(ul.dataLoader.wait, func() {
			ul.executeBatch(ctx)
		})
	}
	
	// Execute immediately if batch is full
	if len(ul.batch) >= ul.dataLoader.maxBatchSize {
		if ul.timer != nil {
			ul.timer.Stop()
		}
		ul.executeBatch(ctx)
	}
	ul.batchMutex.Unlock()
	
	// Wait for batch execution and return from cache
	time.Sleep(ul.dataLoader.wait + 1*time.Millisecond)
	
	ul.mutex.RLock()
	user, exists := ul.cache[userID]
	ul.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("user not found: %s", userID)
	}
	
	return user, nil
}

// executeBatch executes the batched user requests
func (ul *UserLoader) executeBatch(ctx context.Context) {
	ul.batchMutex.Lock()
	batch := make([]string, len(ul.batch))
	copy(batch, ul.batch)
	ul.batch = ul.batch[:0] // Clear batch
	ul.batchMutex.Unlock()
	
	if len(batch) == 0 {
		return
	}
	
	// Load users from gRPC service
	for _, userID := range batch {
		authClient, err := ul.dataLoader.grpcClient.AuthService(ctx)
		if err != nil {
			continue
		}
		
		resp, err := authClient.GetUser(ctx, &authpb.GetUserRequest{
			UserId: userID,
		})
		
		if err != nil {
			continue
		}
		
		// Only skip if we don't have a user AND there's an error
		if resp.Error != "" && resp.User == nil {
			continue
		}
		
		user := helpers.ConvertProtoUserToGraphQL(resp.User)
		
		ul.mutex.Lock()
		ul.cache[userID] = user
		ul.mutex.Unlock()
	}
}

// UserRoleLoader handles batched user role loading
type UserRoleLoader struct {
	dataLoader *DataLoader
	cache      map[string][]*model.Role
	mutex      sync.RWMutex
}

// NewUserRoleLoader creates a new UserRoleLoader
func NewUserRoleLoader(dl *DataLoader) *UserRoleLoader {
	return &UserRoleLoader{
		dataLoader: dl,
		cache:      make(map[string][]*model.Role),
	}
}

// Load loads roles for a user
func (url *UserRoleLoader) Load(ctx context.Context, userID string) ([]*model.Role, error) {
	// Check cache first
	url.mutex.RLock()
	if roles, exists := url.cache[userID]; exists {
		url.mutex.RUnlock()
		return roles, nil
	}
	url.mutex.RUnlock()
	
	// Load user to get roles
	authClient, err := url.dataLoader.grpcClient.AuthService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth client: %w", err)
	}
	
	resp, err := authClient.GetUser(ctx, &authpb.GetUserRequest{
		UserId: userID,
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to load user roles: %w", err)
	}
	
	// Only return error if we don't have a user AND there's an error
	if resp.Error != "" && resp.User == nil {
		return nil, fmt.Errorf("failed to load user roles: %s", resp.Error)
	}
	
	// The new User struct doesn't have Roles field
	// Roles are now managed separately and would need to be retrieved via separate gRPC calls
	// For now, return empty roles array
	roles := []*model.Role{}
	
	// Cache the result
	url.mutex.Lock()
	url.cache[userID] = roles
	url.mutex.Unlock()
	
	return roles, nil
}

// UserPermissionLoader handles batched user permission loading
type UserPermissionLoader struct {
	dataLoader *DataLoader
	cache      map[string][]*model.Permission
	mutex      sync.RWMutex
}

// NewUserPermissionLoader creates a new UserPermissionLoader
func NewUserPermissionLoader(dl *DataLoader) *UserPermissionLoader {
	return &UserPermissionLoader{
		dataLoader: dl,
		cache:      make(map[string][]*model.Permission),
	}
}

// Load loads permissions for a user
func (upl *UserPermissionLoader) Load(ctx context.Context, userID string) ([]*model.Permission, error) {
	// Check cache first
	upl.mutex.RLock()
	if permissions, exists := upl.cache[userID]; exists {
		upl.mutex.RUnlock()
		return permissions, nil
	}
	upl.mutex.RUnlock()
	
	// Load user to get permissions
	authClient, err := upl.dataLoader.grpcClient.AuthService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth client: %w", err)
	}
	
	resp, err := authClient.GetUser(ctx, &authpb.GetUserRequest{
		UserId: userID,
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to load user permissions: %w", err)
	}
	
	// Only return error if we don't have a user AND there's an error
	if resp.Error != "" && resp.User == nil {
		return nil, fmt.Errorf("failed to load user permissions: %s", resp.Error)
	}
	
	// The new User struct doesn't have Permissions field
	// Permissions are now managed separately and would need to be retrieved via separate gRPC calls
	// For now, return empty permissions array
	permissions := []*model.Permission{}
	
	// Cache the result
	upl.mutex.Lock()
	upl.cache[userID] = permissions
	upl.mutex.Unlock()
	
	return permissions, nil
}

