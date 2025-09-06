#!/bin/bash

# NetworkMapper Network Setup Script
# This script configures the application for network access with dynamic IP detection

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() { echo -e "${BLUE}🌐 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

print_info "Setting up NetworkMapper for network access..."

# Auto-generate network configuration if it doesn't exist or if requested
if [ ! -f ".env.network" ] || [ "$1" = "--auto" ] || [ "$1" = "--detect" ]; then
    print_info "Generating dynamic network configuration..."
    
    # Run the network detection script
    if [ -f "scripts/detect-network-config.sh" ]; then
        bash scripts/detect-network-config.sh
    else
        print_warning "Dynamic detection script not found, using fallback method..."
        
        # Fallback: simple IP detection
        DETECTED_IP=$(hostname -I | awk '{print $1}')
        if [[ -z "$DETECTED_IP" || "$DETECTED_IP" == "127.0.0.1" ]]; then
            # Try alternative method
            DETECTED_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP '(?<=src\s)\d+(\.\d+){3}' | head -1)
        fi
        
        if [[ -n "$DETECTED_IP" && "$DETECTED_IP" != "127.0.0.1" ]]; then
            print_info "Detected IP: $DETECTED_IP"
            cat > .env.network << EOF
# Network configuration for external access
# Auto-generated on $(date)
HOST_IP=$DETECTED_IP

# Frontend will connect to this backend URL
REACT_APP_API_URL=http://$DETECTED_IP:8000

# Backend will allow CORS from these origins
CORS_ORIGINS=http://localhost:3000,http://$DETECTED_IP:3000
EOF
            print_success "Generated .env.network with IP: $DETECTED_IP"
        else
            echo "❌ Could not detect network IP automatically"
            echo "Please create .env.network manually or check your network configuration"
            exit 1
        fi
    fi
elif [ ! -f ".env.network" ]; then
    echo "❌ .env.network file not found!"
    echo "💡 Run with --auto flag to generate automatically: ./setup-network.sh --auto"
    exit 1
fi

# Read the configured IP from .env.network
CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
if [[ -z "$CONFIGURED_IP" ]]; then
    CONFIGURED_IP=$(hostname -I | awk '{print $1}')
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
print_info "To regenerate network config: ./setup-network.sh --auto"