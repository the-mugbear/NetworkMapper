#!/bin/bash

# NetworkMapper Network Setup Script
# This script configures the application for network access

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_info() { echo -e "${BLUE}🌐 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

print_info "Setting up NetworkMapper for network access..."

# Check if .env.network exists
if [ ! -f ".env.network" ]; then
    print_error ".env.network file not found!"
    echo "💡 Please create .env.network manually with the following format:"
    echo ""
    echo "HOST_IP=YOUR_SERVER_IP"
    echo "REACT_APP_API_URL=http://YOUR_SERVER_IP:8000"
    echo "CORS_ORIGINS=http://localhost:3000,http://YOUR_SERVER_IP:3000"
    echo ""
    echo "Replace YOUR_SERVER_IP with your actual server IP address."
    exit 1
fi

# Read the configured IP from .env.network
CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
if [[ -z "$CONFIGURED_IP" ]]; then
    print_error "HOST_IP not found in .env.network!"
    echo "Please ensure .env.network contains a HOST_IP setting."
    exit 1
fi

# Stop and remove all containers, networks, and volumes
print_info "Stopping and removing all containers..."
docker-compose down --remove-orphans

# Aggressive cache busting - remove ALL related images and caches
print_info "Performing aggressive cache cleanup to prevent stale code..."

# Remove all NetworkMapper images (including intermediate layers)
docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true

# Remove all unused images, containers, networks, and build cache
print_info "Cleaning Docker build cache and unused resources..."
docker system prune -a -f --volumes

# Remove Docker build cache entirely
print_info "Clearing Docker buildx cache..."
docker builder prune -a -f || true

# Load environment variables and build with no-cache flag and cache-busting
print_info "Building containers with NO CACHE to ensure fresh code..."
CACHE_BUST_VALUE=$(date +%s)
print_info "Using cache-bust value: $CACHE_BUST_VALUE"

docker-compose --env-file .env.network build --no-cache --pull \
    --build-arg CACHE_BUST=$CACHE_BUST_VALUE
docker-compose --env-file .env.network up --force-recreate -d

# Wait a moment for containers to start
print_info "Waiting for containers to start..."
sleep 15

# Check container status
print_info "Container Status:"
docker-compose ps

# Verify backend is running with correct CORS settings
print_info "Verifying backend CORS configuration..."
sleep 5
docker-compose logs backend | grep "CORS origins" | tail -1 || echo "⚠️  CORS logging not found"

# Test API connectivity and verify version
print_info "Testing API connectivity and verifying version..."
if curl -s "http://$CONFIGURED_IP:8000/health" > /dev/null; then
    print_success "Backend API is responding"
    
    # Verify backend version
    API_VERSION=$(curl -s "http://$CONFIGURED_IP:8000/" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
    if [[ "$API_VERSION" == "1.1.0" ]]; then
        print_success "Backend version verified: $API_VERSION"
    else
        print_error "Backend version mismatch! Expected 1.1.0, got: $API_VERSION"
        print_warning "This indicates Docker cache issues - code may not be updated"
    fi
else
    print_error "Backend API is not responding"
fi

# Test frontend and check for .gnmap support
print_info "Verifying frontend deployment..."
if curl -s "http://$CONFIGURED_IP:3000" > /dev/null; then
    print_success "Frontend is responding"
    
    # Check if frontend contains .gnmap support
    FRONTEND_CONTENT=$(curl -s "http://$CONFIGURED_IP:3000" 2>/dev/null || echo "")
    if echo "$FRONTEND_CONTENT" | grep -q "gnmap"; then
        print_success "Frontend contains .gnmap support"
    else
        print_warning "Frontend may not have .gnmap support - possible cache issue"
    fi
else
    print_error "Frontend is not responding"
fi

echo ""
print_success "NetworkMapper is now accessible on the network!"
echo "🖥️  Frontend: http://$CONFIGURED_IP:3000"
echo "🔧 Backend API: http://$CONFIGURED_IP:8000" 
echo "🗄️  Database: Only accessible internally (secure)"
echo ""
print_info "Configuration Details:"
echo "   IP Address: $CONFIGURED_IP"
echo "   CORS Origins: http://localhost:3000,http://$CONFIGURED_IP:3000"
echo "   Environment: Production Network Mode"
echo ""
print_info "To modify network config: edit .env.network and run ./setup-network.sh"