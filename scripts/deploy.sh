#!/bin/bash

# NetworkMapper Unified Deployment Script
# Uses single docker-compose.yml with environment-based configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

print_info() { echo -e "${BLUE}🚀 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_header() { echo -e "${PURPLE}🔧 $1${NC}"; }

# Change to project root
cd "$PROJECT_ROOT"

echo "=============================================="
echo "   NetworkMapper Unified Deployment Script"
echo "=============================================="
echo ""

print_header "NetworkMapper Deployment Options"
echo ""
echo "1) 🖥️  Local Development (HTTP)"
echo "   - Quick local development setup"
echo "   - HTTP only (ports 3000/8000)"
echo "   - No SSL certificates needed"
echo ""
echo "2) 🚀 Production Network (HTTPS)"
echo "   - Secure production deployment"
echo "   - HTTPS with SSL certificates"
echo "   - Uses .env.network configuration"
echo ""
echo "3) 🧪 Test Instance (HTTP)"
echo "   - Parallel test deployment"
echo "   - Alternate ports (3001/8001/5433)"
echo "   - Separate database"
echo ""
echo "4) 💥 Nuclear Clean Deploy"
echo "   - Complete system reset"
echo "   - ⚠️  WARNING: Destroys ALL data"
echo ""
echo "Enter your choice (1-4): "
read -r DEPLOY_CHOICE

case $DEPLOY_CHOICE in
    1)
        print_header "Local Development Deployment"
        print_info "Setting up local development environment..."

        # Stop any existing containers
        docker-compose down --remove-orphans 2>/dev/null || true

        # Use development environment
        export ENV_FILE=.env.development

        print_info "Building and starting development containers..."
        docker-compose --env-file .env.development up --build -d

        print_info "Waiting for services to start..."
        sleep 15

        # Verify deployment
        if curl -s "http://localhost:8000/api/v1/health" > /dev/null; then
            print_success "Backend responding on http://localhost:8000/api/v1"
        else
            print_error "Backend not responding"
        fi

        if curl -s "http://localhost:3000" > /dev/null; then
            print_success "Frontend responding on http://localhost:3000"
        else
            print_error "Frontend not responding"
        fi

        print_success "Development deployment complete!"
        echo "🖥️  Frontend: http://localhost:3000"
        echo "🔧 Backend: http://localhost:8000/api/v1"
        echo "📊 API Docs: http://localhost:8000/docs"
        ;;

    2)
        print_header "Production Network Deployment"
        print_info "Setting up secure production environment..."

        # Check if .env.network exists
        if [[ ! -f ".env.network" ]]; then
            print_error ".env.network file not found!"
            echo "💡 Please create .env.network with HTTPS URLs:"
            echo ""
            echo "HOST_IP=YOUR_SERVER_IP"
            echo "REACT_APP_API_URL=https://YOUR_SERVER_IP"
            echo "CORS_ORIGINS=https://YOUR_SERVER_IP"
            echo ""
            exit 1
        fi

        # Get configured IP
        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)

        # Check/generate SSL certificates
        if [[ ! -f "ssl/certs/networkmapper.crt" || ! -f "ssl/certs/networkmapper.key" ]]; then
            print_warning "SSL certificates not found. Generating for IP: $CONFIGURED_IP"
            if [[ -x "scripts/generate-ssl-cert-simple.sh" ]]; then
                # Remove any partial certificate files to avoid prompts
                rm -f ssl/certs/networkmapper.key ssl/certs/networkmapper.crt ssl/certs/openssl.conf
                ./scripts/generate-ssl-cert-simple.sh "$CONFIGURED_IP"
            else
                print_error "SSL certificate generation script not found!"
                exit 1
            fi
        else
            print_info "Using existing SSL certificates"
        fi

        # Stop existing containers
        print_info "Stopping existing containers..."
        docker-compose down --remove-orphans 2>/dev/null || true

        # Build and start with production configuration
        print_info "Building and starting production containers..."

        # Create temporary compose override for SSL mode
        cat > docker-compose.override.yml << 'EOF'
services:
  backend:
    ports: []  # No external ports in SSL mode
  frontend:
    ports:
      - "443:443"
EOF

        CACHE_BUST=$(date +%s) \
        SSL_MODE=true \
        NGINX_CONFIG=./ssl-nginx.conf \
        docker-compose --env-file .env.network up --build -d

        print_info "Waiting for services to start..."
        sleep 20

        # Verify deployment
        if curl -k -s "https://$CONFIGURED_IP/api/v1/health" > /dev/null; then
            print_success "Backend responding on https://$CONFIGURED_IP/api/v1"
        else
            print_error "Backend not responding on HTTPS"
            print_info "Check logs: docker-compose logs"
        fi

        if curl -k -s "https://$CONFIGURED_IP" > /dev/null; then
            print_success "Frontend responding on https://$CONFIGURED_IP"
        else
            print_error "Frontend not responding on HTTPS"
        fi

        # Clean up temporary override file
        rm -f docker-compose.override.yml

        print_success "Production deployment complete!"
        echo "🔒 Frontend: https://$CONFIGURED_IP"
        echo "🔧 Backend: https://$CONFIGURED_IP/api/v1"
        echo "📊 API Docs: https://$CONFIGURED_IP/docs"
        ;;

    3)
        print_header "Test Instance Deployment"
        print_info "Setting up test environment on alternate ports..."

        # Stop any existing test containers
        docker-compose down --remove-orphans 2>/dev/null || true

        # Build and start test instance
        print_info "Building and starting test containers..."
        docker-compose --env-file .env.test up --build -d

        print_info "Waiting for services to start..."
        sleep 15

        # Verify deployment
        if curl -s "http://localhost:8001/api/v1/health" > /dev/null; then
            print_success "Backend responding on http://localhost:8001/api/v1"
        else
            print_error "Backend not responding"
        fi

        if curl -s "http://localhost:3001" > /dev/null; then
            print_success "Frontend responding on http://localhost:3001"
        else
            print_error "Frontend not responding"
        fi

        print_success "Test deployment complete!"
        echo "🧪 Frontend: http://localhost:3001"
        echo "🔧 Backend: http://localhost:8001/api/v1"
        echo "📊 API Docs: http://localhost:8001/docs"
        ;;

    4)
        print_header "Nuclear Clean Deploy"
        print_warning "⚠️  WARNING: This will destroy ALL data including database!"
        echo "Type 'DELETE EVERYTHING' to confirm: "
        read -r CONFIRM

        if [[ "$CONFIRM" != "DELETE EVERYTHING" ]]; then
            print_info "Operation cancelled"
            exit 0
        fi

        print_warning "Nuclear cleanup - destroying all containers and data..."

        # Nuclear cleanup
        docker-compose down --remove-orphans --volumes 2>/dev/null || true
        docker stop $(docker ps -aq) 2>/dev/null || true
        docker rm -f $(docker ps -aq) 2>/dev/null || true
        docker rmi -f $(docker images -aq) 2>/dev/null || true
        docker system prune -a -f --volumes
        docker builder prune -a -f || true

        print_success "Nuclear cleanup complete! System reset."
        print_info "You can now run this script again to deploy fresh."
        ;;

    *)
        print_error "Invalid choice. Please select 1-4."
        exit 1
        ;;
esac

echo ""
print_success "🎉 Deployment completed!"
echo ""
print_info "Useful commands:"
echo "  📋 Collect logs: ./scripts/collect-logs.sh"
echo "  👥 Setup users: ./scripts/setup-users.sh"
echo "  📊 Container status: docker-compose ps"
echo "  📝 View logs: docker-compose logs [service]"
echo "  🔄 Restart service: docker-compose restart [service]"
echo "  🛑 Stop all: docker-compose down"
echo ""