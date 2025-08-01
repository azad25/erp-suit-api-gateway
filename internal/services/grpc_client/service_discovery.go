// service/grpc_client/service_discovery.go
package grpc_client

import (
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/consul/api"
	"erp-api-gateway/internal/config"
	"erp-api-gateway/internal/logging"
)

// ServiceDiscovery defines the interface for service discovery
type ServiceDiscovery interface {
	GetServiceAddress(serviceName string) (string, error)
	WatchService(serviceName string, updateChan chan<- string)
	Close() error
}

// ConsulServiceDiscovery implements service discovery using Consul
type ConsulServiceDiscovery struct {
	client      *api.Client
	logger      logging.Logger
	config      *config.GRPCConfig
	updateChans map[string]chan<- string
	mutex       sync.RWMutex
	closed      bool
}

// NewConsulServiceDiscovery creates a new Consul service discovery client
func NewConsulServiceDiscovery(cfg *config.GRPCConfig, logger logging.Logger) (*ConsulServiceDiscovery, error) {
	config := api.DefaultConfig()
	config.Address = cfg.ConsulAddress
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	return &ConsulServiceDiscovery{
		client:      client,
		logger:      logger,
		config:      cfg,
		updateChans: make(map[string]chan<- string),
	}, nil
}

// GetServiceAddress retrieves the address for a service
func (d *ConsulServiceDiscovery) GetServiceAddress(serviceName string) (string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if d.closed {
		return "", fmt.Errorf("service discovery is closed")
	}

	services, _, err := d.client.Health().Service(serviceName, "", true, nil)
	if err != nil {
		return "", fmt.Errorf("failed to query service %s: %w", serviceName, err)
	}

	if len(services) == 0 {
		return "", fmt.Errorf("no healthy instances found for service %s", serviceName)
	}

	// Return the first healthy instance
	service := services[0]
	return fmt.Sprintf("%s:%d", service.Service.Address, service.Service.Port), nil
}

// WatchService watches for service address updates
func (d *ConsulServiceDiscovery) WatchService(serviceName string, updateChan chan<- string) {
	d.mutex.Lock()
	d.updateChans[serviceName] = updateChan
	d.mutex.Unlock()

	go func() {
		var lastIndex uint64
		for {
			d.mutex.RLock()
			if d.closed {
				d.mutex.RUnlock()
				return
			}
			d.mutex.RUnlock()

			services, meta, err := d.client.Health().Service(serviceName, "", true, &api.QueryOptions{WaitIndex: lastIndex})
			if err != nil {
				d.logger.Error("Failed to watch service",
					map[string]interface{}{
						"service": serviceName,
						"error":   err.Error(),
					})
				time.Sleep(time.Second * 5) // Backoff on error
				continue
			}

			if lastIndex != meta.LastIndex {
				lastIndex = meta.LastIndex
				if len(services) > 0 {
					address := fmt.Sprintf("%s:%d", services[0].Service.Address, services[0].Service.Port)
					updateChan <- address
				}
			}

			time.Sleep(time.Second) // Prevent tight loop
		}
	}()
}

// Close shuts down the service discovery client
func (d *ConsulServiceDiscovery) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	for _, ch := range d.updateChans {
		close(ch)
	}
	return nil
}

// ServiceEndpoints holds static service endpoints
type ServiceEndpoints struct {
	AuthService    string
	CRMService     string
	HRMService     string
	FinanceService string
}