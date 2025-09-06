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

# Stop current containers
print_info "Stopping current containers..."
docker-compose down

# Load environment variables and start containers  
print_info "Starting containers with network configuration..."
docker-compose --env-file .env.network up -d

# Wait a moment for containers to start
print_info "Waiting for containers to start..."
sleep 10

# Check container status
print_info "Container Status:"
docker-compose ps

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