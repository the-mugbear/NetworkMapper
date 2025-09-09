#!/bin/bash

# ULTRA-AGGRESSIVE DEPLOYMENT SCRIPT
# For when Docker cache refuses to cooperate

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${BLUE}🚀 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

print_warning "ULTRA-AGGRESSIVE DEPLOYMENT MODE"
print_info "This will completely rebuild everything from scratch"

# Check if .env.network exists
if [ ! -f ".env.network" ]; then
    print_error ".env.network file not found!"
    exit 1
fi

CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
print_info "Deploying to IP: $CONFIGURED_IP"

# Step 1: Stop and destroy everything
print_info "Step 1: Destroying all containers and data..."
docker-compose --env-file .env.network down --remove-orphans --volumes || true
docker stop $(docker ps -aq) 2>/dev/null || true
docker rm -f $(docker ps -aq) 2>/dev/null || true

# Step 2: Remove ALL NetworkMapper images
print_info "Step 2: Removing ALL NetworkMapper images..."
docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true
docker images | grep -E "frontend|backend" | awk '{print $3}' | xargs -r docker rmi -f || true

# Step 3: Nuclear system cleanup
print_info "Step 3: Nuclear Docker cleanup..."
docker system prune -a -f --volumes
docker builder prune -a -f
docker buildx prune -a -f || true

# Step 4: Clear ALL possible caches
print_info "Step 4: Clearing all build caches..."
rm -rf frontend/node_modules || true
rm -rf frontend/.next || true
rm -rf frontend/build || true
rm -rf backend/__pycache__ || true
rm -rf backend/**/__pycache__ || true
find . -name "*.pyc" -delete || true

# Step 5: Invalidate Dockerfiles by touching them
print_info "Step 5: Invalidating Docker layers..."
touch frontend/Dockerfile
touch backend/Dockerfile
sleep 1

# Step 6: Ultra cache-bust build
print_info "Step 6: Building with ultra cache-busting..."
ULTRA_CACHE_BUST=$(date +%s%N)  # Nanosecond precision
print_info "Ultra cache-bust value: $ULTRA_CACHE_BUST"

# Build frontend with no cache
print_info "Building frontend with --no-cache..."
docker build --no-cache --pull --build-arg CACHE_BUST=$ULTRA_CACHE_BUST -t networkmapper_frontend:latest frontend/

# Build backend with no cache  
print_info "Building backend with --no-cache..."
docker build --no-cache --pull --build-arg CACHE_BUST=$ULTRA_CACHE_BUST -t networkmapper_backend:latest backend/

# Step 7: Start with force recreate
print_info "Step 7: Starting containers with force recreate..."
docker-compose --env-file .env.network up --force-recreate -d

# Step 8: Wait for startup
print_info "Step 8: Waiting for services to start..."
sleep 30

# Step 9: Verify deployment
print_info "Step 9: Verifying deployment..."

# Check backend
if curl -s "http://$CONFIGURED_IP:8000/health" > /dev/null; then
    API_VERSION=$(curl -s "http://$CONFIGURED_IP:8000/" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
    if [[ "$API_VERSION" == "1.2.0" ]]; then
        print_success "Backend version correct: $API_VERSION"
    else
        print_error "Backend version wrong! Expected 1.2.0, got: $API_VERSION"
    fi
else
    print_error "Backend not responding"
fi

# Check frontend
if curl -s "http://$CONFIGURED_IP:3000" > /dev/null; then
    FRONTEND_CONTENT=$(curl -s "http://$CONFIGURED_IP:3000" 2>/dev/null || echo "")
    
    # Check for version 1.4.0
    if echo "$FRONTEND_CONTENT" | grep -q "1\.4\.0"; then
        print_success "Frontend version correct: 1.4.0"
    else
        print_warning "Frontend version may be incorrect"
    fi
    
    # Check for .gnmap support
    if echo "$FRONTEND_CONTENT" | grep -q "gnmap"; then
        print_success "Frontend contains .gnmap support"
    else
        print_error "Frontend STILL missing .gnmap support - critical cache issue!"
        print_warning "Consider checking browser cache or network caching"
    fi
    
    # Check supported formats text
    if echo "$FRONTEND_CONTENT" | grep -q "\.xml.*gnmap.*\.json"; then
        print_success "Upload formats display .gnmap support"
    else
        print_warning "Upload formats may not show .gnmap"
    fi
    
else
    print_error "Frontend not responding"
fi

print_success "Ultra-aggressive deployment complete!"
echo ""
print_info "Frontend: http://$CONFIGURED_IP:3000"
print_info "Backend: http://$CONFIGURED_IP:8000"
echo ""
print_warning "If .gnmap support STILL doesn't appear:"
print_warning "1. Clear browser cache (Ctrl+Shift+Del)"
print_warning "2. Try private/incognito window"
print_warning "3. Check if there's a reverse proxy/CDN caching"
print_warning "4. Verify network/DNS isn't caching old content"