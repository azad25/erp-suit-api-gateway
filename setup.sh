#!/bin/bash

# ERP Core API Gateway Setup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for service to be ready
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    print_status "Waiting for $service to be ready on port $port..."
    
    while [ $attempt -le $max_attempts ]; do
        if nc -z localhost $port 2>/dev/null; then
            print_success "$service is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "$service failed to start within expected time"
    return 1
}

# Main setup function
main() {
    echo "🚀 ERP Core API Gateway Setup"
    echo "=============================="
    echo ""
    
    # Check prerequisites
    print_status "Checking prerequisites..."
    
    if ! command_exists python3; then
        print_error "Python 3 is not installed. Please install Python 3.11+ first."
        exit 1
    fi
    
    if ! command_exists pip3; then
        print_error "pip3 is not installed. Please install pip3 first."
        exit 1
    fi
    
    if ! command_exists docker; then
        print_warning "Docker is not installed. You can still run locally."
    fi
    
    if ! command_exists docker-compose; then
        print_warning "Docker Compose is not installed. You can still run locally."
    fi
    
    print_success "Prerequisites check completed!"
    echo ""
    
    # Create necessary directories
    print_status "Creating directories..."
    mkdir -p logs
    mkdir -p media
    mkdir -p staticfiles
    print_success "Directories created!"
    echo ""
    
    # Install dependencies
    print_status "Installing Python dependencies..."
    pip3 install -r requirements.txt
    print_success "Dependencies installed!"
    echo ""
    
    # Check if we should run with Docker or locally
    if command_exists docker && command_exists docker-compose; then
        print_status "Docker detected. Setting up with Docker..."
        
        # Check if infrastructure is running
        if docker ps | grep -q "erp-postgres"; then
            print_success "Infrastructure is already running!"
        else
            print_warning "Infrastructure not detected. Please start it first:"
            echo "   cd ../infrastructure && make dev-up"
            echo ""
        fi
        
        # Build and run Django core
        print_status "Building and starting Django core..."
        docker-compose build
        docker-compose up -d
        
        # Wait for service to be ready
        wait_for_service "Django Core" 8000
        
        print_success "Django Core API Gateway is running!"
        echo ""
        print_status "Service URLs:"
        echo "   API Gateway: http://localhost:8000"
        echo "   API Docs: http://localhost:8000/api/docs/"
        echo "   Health Check: http://localhost:8000/health/"
        echo "   Admin: http://localhost:8000/admin/"
        
    else
        print_status "Setting up for local development..."
        
        # Check if infrastructure is running
        if nc -z localhost 5432 2>/dev/null; then
            print_success "PostgreSQL is running!"
        else
            print_warning "PostgreSQL not detected. Please start infrastructure first:"
            echo "   cd ../infrastructure && make dev-up"
            echo ""
        fi
        
        if nc -z localhost 6379 2>/dev/null; then
            print_success "Redis is running!"
        else
            print_warning "Redis not detected. Please start infrastructure first:"
            echo "   cd ../infrastructure && make dev-up"
            echo ""
        fi
        
        if nc -z localhost 8080 2>/dev/null; then
            print_success "Auth Service is running!"
        else
            print_warning "Auth Service not detected. Please start it first:"
            echo "   cd ../auth-module && make dev"
            echo ""
        fi
        
        # Run migrations
        print_status "Running database migrations..."
        python3 manage.py migrate
        print_success "Migrations completed!"
        
        # Collect static files
        print_status "Collecting static files..."
        python3 manage.py collectstatic --noinput
        print_success "Static files collected!"
        
        print_success "Local setup completed!"
        echo ""
        print_status "To start the development server:"
        echo "   make dev"
        echo ""
        print_status "Or run:"
        echo "   python3 manage.py runserver 0.0.0.0:8000"
    fi
    
    echo ""
    print_success "Setup completed successfully! 🎉"
    echo ""
    print_status "Next steps:"
    echo "   1. Test the API: python3 test_auth_integration.py"
    echo "   2. Visit the API documentation: http://localhost:8000/api/docs/"
    echo "   3. Check health status: http://localhost:8000/health/"
    echo "   4. Start building your ERP modules!"
}

# Run main function
main "$@" 