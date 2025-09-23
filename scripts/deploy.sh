#!/bin/bash

# NetworkMapper Unified Deployment Script
# Consolidates all deployment options into one script with user choices

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

print_header "NetworkMapper Production Deployment"
echo ""
echo "This script deploys NetworkMapper in production mode with HTTPS security."
echo ""
echo "Features:"
echo "🔒 HTTPS-only with self-signed certificates"
echo "🛡️  Security-hardened configuration"
echo "🚀 Production-ready deployment"
echo "📊 Comprehensive logging and monitoring"
echo ""
echo "Deployment Options:"
echo ""
echo "1) 🚀 Standard Production Deploy"
echo "   - Clean deployment with existing cache"
echo "   - Preserves database data"
echo "   - Quick startup for normal deployments"
echo ""
echo "2) 🔄 Clean Production Deploy"
echo "   - Removes application images and rebuilds"
echo "   - Preserves database data"
echo "   - Use for application updates"
echo ""
echo "3) 💥 Nuclear Production Deploy"
echo "   - Complete system reset and rebuild"
echo "   - ⚠️  WARNING: Destroys ALL data including database"
echo "   - Use only for complete fresh start"
echo ""
echo "Enter your choice (1-3): "
read -r DEPLOY_CHOICE

case $DEPLOY_CHOICE in
    1)
        print_header "Standard Production Deploy"
        print_info "Quick deployment with existing cache..."

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

        # Check if SSL certificates exist
        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        if [[ ! -f "ssl/certs/networkmapper.crt" || ! -f "ssl/certs/networkmapper.key" ]]; then
            print_warning "SSL certificates not found. Generating for IP: $CONFIGURED_IP"
            if [[ -x "scripts/generate-ssl-cert.sh" ]]; then
                ./scripts/generate-ssl-cert.sh -d "$CONFIGURED_IP" -s localhost -s 127.0.0.1
            else
                print_error "SSL certificate generation script not found!"
                exit 1
            fi
        else
            print_info "Using existing SSL certificates"
        fi

        print_info "Deploying production to network IP: $CONFIGURED_IP"

        # Stop existing containers
        print_info "Stopping existing containers..."
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml down --remove-orphans

        # Standard build with cache
        print_info "Building with existing cache..."
        CACHE_BUST=$(date +%s)
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml build --build-arg CACHE_BUST=$CACHE_BUST

        # Start production
        print_info "Starting production containers..."
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml up --force-recreate -d

        print_info "Waiting for services to start..."
        sleep 20

        # Verify deployment
        if curl -k -s "https://$CONFIGURED_IP/api/v1/health" > /dev/null; then
            print_success "Backend responding on https://$CONFIGURED_IP/api/v1"
        else
            print_error "Backend not responding"
        fi

        if curl -k -s "https://$CONFIGURED_IP" > /dev/null; then
            print_success "Frontend responding on https://$CONFIGURED_IP"
        else
            print_error "Frontend not responding"
        fi

        print_success "Standard production deployment complete!"
        echo "🔒 Frontend: https://$CONFIGURED_IP"
        echo "🔧 Backend: https://$CONFIGURED_IP/api/v1"
        echo "📊 API Docs: https://$CONFIGURED_IP/docs"
        ;;

    2)
        print_header "Clean Production Deploy"
        print_info "Clean deployment with application rebuild..."

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

        # Check if SSL certificates exist
        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        if [[ ! -f "ssl/certs/networkmapper.crt" || ! -f "ssl/certs/networkmapper.key" ]]; then
            print_warning "SSL certificates not found. Generating for IP: $CONFIGURED_IP"
            if [[ -x "scripts/generate-ssl-cert.sh" ]]; then
                ./scripts/generate-ssl-cert.sh -d "$CONFIGURED_IP" -s localhost -s 127.0.0.1
            else
                print_error "SSL certificate generation script not found!"
                exit 1
            fi
        else
            print_info "Using existing SSL certificates"
        fi

        print_info "Clean deploying to network IP: $CONFIGURED_IP"

        # Stop existing containers (preserve database)
        print_info "Stopping existing containers..."
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml down --remove-orphans

        # Clean build - remove application images
        print_info "Removing application images..."
        docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true

        print_info "Building clean application..."
        CACHE_BUST=$(date +%s%N)
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml build --no-cache --build-arg CACHE_BUST=$CACHE_BUST

        # Start production
        print_info "Starting production containers..."
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml up --force-recreate -d

        print_info "Waiting for services to start..."
        sleep 20

        # Verify deployment
        if curl -k -s "https://$CONFIGURED_IP/api/v1/health" > /dev/null; then
            print_success "Backend responding on https://$CONFIGURED_IP/api/v1"
        else
            print_error "Backend not responding"
        fi

        if curl -k -s "https://$CONFIGURED_IP" > /dev/null; then
            print_success "Frontend responding on https://$CONFIGURED_IP"
        else
            print_error "Frontend not responding"
        fi

        print_success "Clean production deployment complete!"
        echo "🔒 Frontend: https://$CONFIGURED_IP"
        echo "🔧 Backend: https://$CONFIGURED_IP/api/v1"
        echo "📊 API Docs: https://$CONFIGURED_IP/docs"
        ;;

    3)
        print_header "Nuclear Production Deploy"
        print_warning "⚠️  WARNING: This will destroy ALL data including database!"
        echo "Type 'DELETE EVERYTHING' to confirm: "
        read -r CONFIRM

        if [[ "$CONFIRM" != "DELETE EVERYTHING" ]]; then
            print_info "Operation cancelled"
            exit 0
        fi

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

        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        print_warning "Nuclear deployment to network IP: $CONFIGURED_IP"

        # Nuclear cleanup
        print_info "Destroying all containers and data..."
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml down --remove-orphans --volumes || true
        docker stop $(docker ps -aq) 2>/dev/null || true
        docker rm -f $(docker ps -aq) 2>/dev/null || true
        docker rmi -f $(docker images -aq) 2>/dev/null || true
        docker system prune -a -f --volumes
        docker builder prune -a -f || true

        print_success "Nuclear cleanup complete!"

        # Generate SSL certificates
        if [[ -x "scripts/generate-ssl-cert.sh" ]]; then
            print_info "Generating fresh SSL certificates..."
            ./scripts/generate-ssl-cert.sh -d "$CONFIGURED_IP" -s localhost -s 127.0.0.1
        else
            print_error "SSL certificate generation script not found!"
            exit 1
        fi

        # Nuclear rebuild
        print_info "Rebuilding everything from scratch..."
        CACHE_BUST=$(date +%s%N)
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST

        # Start production
        print_info "Starting fresh production containers..."
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml up --force-recreate -d

        print_info "Waiting for services to start..."
        sleep 30

        # Verify deployment
        if curl -k -s "https://$CONFIGURED_IP/api/v1/health" > /dev/null; then
            print_success "Backend responding on https://$CONFIGURED_IP/api/v1"
        else
            print_error "Backend not responding"
        fi

        if curl -k -s "https://$CONFIGURED_IP" > /dev/null; then
            print_success "Frontend responding on https://$CONFIGURED_IP"
        else
            print_error "Frontend not responding"
        fi

        print_success "Nuclear production deployment complete!"
        echo "🔒 Frontend: https://$CONFIGURED_IP"
        echo "🔧 Backend: https://$CONFIGURED_IP/api/v1"
        echo "📊 API Docs: https://$CONFIGURED_IP/docs"
        ;;

    *)
        print_error "Invalid choice. Please select 1-3."
        exit 1
        ;;
esac

echo ""
print_success "🎉 Deployment completed!"
echo ""
print_info "Default Admin Credentials:"
echo "  👤 Username: admin"
echo "  🔑 Password: admin123"
echo "  📧 Email: admin@example.com (optional)"
echo ""
print_info "Useful commands:"
echo "  📋 Collect logs: ./scripts/collect-logs.sh"
echo "  👥 Setup users: ./scripts/setup-users.sh"
echo "  📊 Container status: docker-compose ps"
echo "  📝 View logs: docker-compose logs [service]"
echo "  🔄 Restart service: docker-compose restart [service]"
echo "  🛑 Stop all: docker-compose down"
echo ""
print_warning "Remember to check logs if services aren't responding as expected!"