#!/bin/bash

# NetworkMapper Nuclear Option - Force Clean Rebuild
# Use this when aggressive caching issues persist

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${BLUE}💥 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

print_warning "NUCLEAR OPTION: This will remove ALL Docker data!"
echo "This will remove:"
echo "- All containers (running and stopped)"
echo "- All images (including system images)"
echo "- All networks (except defaults)"
echo "- All volumes"
echo "- All build cache"
echo ""
read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm

if [[ "$confirm" != "yes" ]]; then
    print_info "Operation cancelled"
    exit 0
fi

print_info "Starting nuclear rebuild process..."

# Stop all containers
print_info "Stopping all Docker containers..."
docker stop $(docker ps -aq) 2>/dev/null || true

# Remove all containers
print_info "Removing all containers..."
docker rm -f $(docker ps -aq) 2>/dev/null || true

# Remove all images
print_info "Removing all Docker images..."
docker rmi -f $(docker images -aq) 2>/dev/null || true

# Remove all networks (except defaults)
print_info "Removing custom networks..."
docker network rm $(docker network ls -q --filter type=custom) 2>/dev/null || true

# Remove all volumes
print_info "Removing all volumes..."
docker volume rm $(docker volume ls -q) 2>/dev/null || true

# Prune everything
print_info "Final system cleanup..."
docker system prune -a -f --volumes

# Clear buildx cache
print_info "Clearing buildx cache..."
docker builder prune -a -f || true

print_success "Nuclear cleanup complete!"

# Check if .env.network exists
if [[ -f ".env.network" ]]; then
    print_info "Found .env.network, proceeding with network deployment..."
    
    # Build and start with aggressive cache busting
    CACHE_BUST_VALUE=$(date +%s%N)  # Nanosecond precision
    print_info "Using ultra-cache-bust value: $CACHE_BUST_VALUE"
    
    print_info "Rebuilding from scratch..."
    docker-compose --env-file .env.network build --no-cache --pull \
        --build-arg CACHE_BUST=$CACHE_BUST_VALUE
    
    print_info "Starting fresh containers..."
    docker-compose --env-file .env.network up --force-recreate -d
    
    print_info "Waiting for containers to stabilize..."
    sleep 20
    
    # Verify deployment
    CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
    print_info "Verifying deployment on $CONFIGURED_IP..."
    
    # Test backend
    if curl -s "http://$CONFIGURED_IP:8000/health" > /dev/null; then
        API_VERSION=$(curl -s "http://$CONFIGURED_IP:8000/" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        print_success "Backend responding - Version: $API_VERSION"
    else
        print_error "Backend not responding"
    fi
    
    # Test frontend
    if curl -s "http://$CONFIGURED_IP:3000" > /dev/null; then
        print_success "Frontend responding"
    else
        print_error "Frontend not responding"
    fi
    
    print_success "Nuclear rebuild complete!"
    echo "🖥️  Frontend: http://$CONFIGURED_IP:3000"
    echo "🔧 Backend: http://$CONFIGURED_IP:8000"
    
else
    print_info "No .env.network found - manual setup required"
    print_info "Use regular docker-compose commands or create .env.network first"
fi

print_warning "Note: You may need to re-pull base images on first run"
print_info "If issues persist, check Docker daemon settings or restart Docker"