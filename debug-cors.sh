#!/bin/bash

# CORS Debug Helper Script
# This script helps diagnose and fix CORS issues when deploying on different hosts

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() { echo -e "${BLUE}🔍 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

print_info "NetworkMapper CORS Debug Tool"
print_info "=============================="

# 1. Check current .env.network configuration
if [ -f ".env.network" ]; then
    print_info "Current .env.network configuration:"
    cat .env.network
    echo ""
    
    # Extract values
    HOST_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
    API_URL=$(grep "^REACT_APP_API_URL=" .env.network | cut -d'=' -f2)
    CORS_ORIGINS=$(grep "^CORS_ORIGINS=" .env.network | cut -d'=' -f2)
    
    print_info "Parsed values:"
    echo "  HOST_IP: $HOST_IP"
    echo "  REACT_APP_API_URL: $API_URL"
    echo "  CORS_ORIGINS: $CORS_ORIGINS"
    echo ""
else
    print_error ".env.network file not found!"
    exit 1
fi

# 2. Check what the backend is actually using
print_info "Checking backend CORS configuration..."
if docker-compose ps | grep -q backend; then
    print_info "Backend container is running. Checking logs for CORS origins..."
    BACKEND_CORS=$(docker-compose logs backend 2>/dev/null | grep "CORS origins:" | tail -1)
    if [ -n "$BACKEND_CORS" ]; then
        echo "  $BACKEND_CORS"
    else
        print_warning "No CORS origins found in backend logs"
    fi
else
    print_warning "Backend container is not running"
fi
echo ""

# 3. Detect current host IP
print_info "Detecting current host IP addresses..."
echo "Method 1 - Default route:"
ip route get 8.8.8.8 2>/dev/null | grep -oP '(?<=src\s)\d+(\.\d+){3}' | head -1 || echo "  Failed"

echo "Method 2 - Hostname -I:"
hostname -I | awk '{print "  " $1}'

echo "Method 3 - All network interfaces:"
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | while read ip; do
    echo "  $ip"
done
echo ""

# 4. Test API connectivity
if [ -n "$HOST_IP" ]; then
    print_info "Testing API connectivity..."
    
    # Test basic connectivity
    if curl -s --connect-timeout 5 "http://$HOST_IP:8000/" > /dev/null; then
        print_success "Backend API is reachable at http://$HOST_IP:8000"
    else
        print_error "Backend API is NOT reachable at http://$HOST_IP:8000"
    fi
    
    # Test CORS preflight for upload endpoint
    print_info "Testing CORS preflight for file upload..."
    ORIGIN="http://$HOST_IP:3000"
    
    CORS_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Origin: $ORIGIN" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Content-Type" \
        -X OPTIONS \
        "http://$HOST_IP:8000/api/v1/upload/subnets" 2>/dev/null || echo "000")
    
    if [ "$CORS_RESPONSE" = "200" ]; then
        print_success "CORS preflight successful for $ORIGIN"
    else
        print_error "CORS preflight failed for $ORIGIN (HTTP $CORS_RESPONSE)"
        echo "  This means the origin $ORIGIN is not in the backend's CORS_ORIGINS list"
    fi
fi
echo ""

# 5. Suggest fixes
print_info "Suggested fixes:"

CURRENT_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP '(?<=src\s)\d+(\.\d+){3}' | head -1)
if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "$HOST_IP" ]; then
    print_warning "Host IP mismatch detected!"
    echo "  .env.network has: $HOST_IP"
    echo "  Current host IP:  $CURRENT_IP"
    echo ""
    echo "  Fix: Update .env.network with current IP:"
    echo "    sed -i 's/$HOST_IP/$CURRENT_IP/g' .env.network"
    echo "    ./setup-network.sh"
    echo ""
fi

# 6. Show how to manually test CORS
print_info "Manual CORS testing:"
echo "1. Open browser developer tools (F12)"
echo "2. Go to Console tab"
echo "3. Run this JavaScript test:"
echo ""
echo "fetch('http://$HOST_IP:8000/api/v1/dashboard/stats', {"
echo "  method: 'GET',"
echo "  headers: { 'Content-Type': 'application/json' }"
echo "})"
echo ".then(r => console.log('CORS OK:', r.status))"
echo ".catch(e => console.log('CORS Error:', e))"
echo ""

print_info "Debug complete!"