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

print_header "Available Deployment Options:"
echo ""
echo "1) 🏠 Local Development (localhost:3000/8000) [INSECURE]"
echo "   - Quick local setup for development"
echo "   - Uses standard Docker Compose"
echo "   - ⚠️  INSECURE: Uses HTTP only - consider option 4 for HTTPS"
echo ""
echo "2) 🌐 Network Production (.env.network required) [INSECURE]"
echo "   - Production deployment on network IP"
echo "   - Requires .env.network configuration"
echo "   - ⚠️  INSECURE: Uses HTTP only - consider option 5 for HTTPS"
echo ""
echo "3) 🧪 Test Instance (localhost:3001/8001)"
echo "   - Test deployment alongside production"
echo "   - Uses separate ports and database"
echo "   - Safe for testing without affecting production"
echo ""
echo "4) 🔒 Local Development with SSL (https://localhost)"
echo "   - HTTPS-enabled local development"
echo "   - Auto-generates self-signed certificates"
echo "   - Accessible via https://localhost"
echo ""
echo "5) 🔐 Network Production with SSL (.env.network + SSL)"
echo "   - HTTPS production deployment"
echo "   - Requires .env.network and SSL certificates"
echo "   - Full production-ready HTTPS setup"
echo ""
echo "6) 💥 Nuclear Clean Rebuild"
echo "   - Removes ALL Docker data and rebuilds"
echo "   - Use when aggressive caching issues persist"
echo "   - WARNING: Destroys all containers, images, volumes"
echo ""
echo "7) 🔧 Network Fresh Deploy"
echo "   - Ultra-aggressive network deployment"
echo "   - Forces complete rebuild with cache busting"
echo "   - For persistent Docker cache issues"
echo ""
echo "Enter your choice (1-7): "
read -r DEPLOY_CHOICE

case $DEPLOY_CHOICE in
    1)
        print_header "Local Development Deployment [INSECURE HTTP]"
        print_warning "This deployment uses HTTP only and is not secure!"
        print_warning "For secure HTTPS deployment, use option 4 instead."
        echo "Continue with insecure HTTP deployment? (y/N): "
        read -r CONTINUE_HTTP
        if [[ ! "$CONTINUE_HTTP" =~ ^[Yy]$ ]]; then
            print_info "Deployment cancelled. Use option 4 for secure HTTPS deployment."
            exit 0
        fi
        print_info "Deploying to localhost for development..."

        # Check if .env.network exists and warn
        if [[ -f ".env.network" ]]; then
            print_warning "Found .env.network - this will be ignored for local deployment"
        fi

        print_info "Cache busting options:"
        echo "1) Quick build (use existing cache)"
        echo "2) Clean build (remove NetworkMapper images only)"
        echo "3) Nuclear build (remove ALL images and cache)"
        echo "Enter choice (1-3): "
        read -r CACHE_CHOICE

        # Stop existing containers
        print_info "Stopping existing containers..."
        docker-compose down --remove-orphans || true

        case $CACHE_CHOICE in
            1)
                print_info "Quick build with existing cache..."
                CACHE_BUST=$(date +%s)
                docker-compose build --build-arg CACHE_BUST=$CACHE_BUST
                ;;
            2)
                print_info "Clean build - removing NetworkMapper images..."
                docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true
                CACHE_BUST=$(date +%s)
                docker-compose build --no-cache --build-arg CACHE_BUST=$CACHE_BUST
                ;;
            3)
                print_info "Nuclear build - removing ALL images and cache..."
                docker system prune -a -f --volumes
                docker builder prune -a -f || true
                CACHE_BUST=$(date +%s%N)
                docker-compose build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST
                ;;
        esac

        print_info "Starting local development containers..."
        docker-compose up --force-recreate -d

        print_info "Waiting for services to start..."
        sleep 15

        # Verify deployment
        if curl -s "http://localhost:8000/health" > /dev/null; then
            print_success "Backend responding on http://localhost:8000"
        else
            print_error "Backend not responding"
        fi

        if curl -s "http://localhost:3000" > /dev/null; then
            print_success "Frontend responding on http://localhost:3000"
        else
            print_error "Frontend not responding"
        fi

        print_success "Local development deployment complete!"
        echo "🖥️  Frontend: http://localhost:3000"
        echo "🔧 Backend: http://localhost:8000"
        echo "📊 API Docs: http://localhost:8000/docs"
        ;;

    2)
        print_header "Network Production Deployment [INSECURE HTTP]"
        print_warning "This deployment uses HTTP only and is not secure for production!"
        print_warning "For secure HTTPS production deployment, use option 5 instead."
        echo "Continue with insecure HTTP deployment? (y/N): "
        read -r CONTINUE_HTTP
        if [[ ! "$CONTINUE_HTTP" =~ ^[Yy]$ ]]; then
            print_info "Deployment cancelled. Use option 5 for secure HTTPS deployment."
            exit 0
        fi

        # Check if .env.network exists
        if [[ ! -f ".env.network" ]]; then
            print_error ".env.network file not found!"
            echo "💡 Please create .env.network with the following format:"
            echo ""
            echo "HOST_IP=YOUR_SERVER_IP"
            echo "REACT_APP_API_URL=http://YOUR_SERVER_IP:8000"
            echo "CORS_ORIGINS=http://localhost:3000,http://YOUR_SERVER_IP:3000"
            echo ""
            echo "Replace YOUR_SERVER_IP with your actual server IP address."
            exit 1
        fi

        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        print_info "Deploying to network IP: $CONFIGURED_IP"

        # Ask about database preservation
        echo "Preserve existing database? (Y/n): "
        read -r PRESERVE_DB

        print_info "Stopping containers..."
        if [[ "$PRESERVE_DB" =~ ^[Nn]$ ]]; then
            docker-compose --env-file .env.network down --remove-orphans --volumes
            print_warning "Database will be reset"
        else
            docker-compose --env-file .env.network down --remove-orphans
            print_info "Database preserved"
        fi

        # Ask about cache busting
        echo "Force complete rebuild (slower but ensures fresh code)? (y/N): "
        read -r CACHE_BUST

        if [[ "$CACHE_BUST" =~ ^[Yy]$ ]]; then
            print_info "Performing aggressive cache cleanup..."
            docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true
            docker system prune -a -f --volumes
            docker builder prune -a -f || true
            touch frontend/Dockerfile backend/Dockerfile

            CACHE_BUST_VALUE=$(date +%s%N)
            docker-compose --env-file .env.network build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST_VALUE
        else
            CACHE_BUST_VALUE=$(date +%s)
            docker-compose --env-file .env.network build --build-arg CACHE_BUST=$CACHE_BUST_VALUE
        fi

        print_info "Starting network containers..."
        docker-compose --env-file .env.network up --force-recreate -d

        print_info "Waiting for services..."
        sleep 20

        # Verify deployment
        if curl -s "http://$CONFIGURED_IP:8000/health" > /dev/null; then
            API_VERSION=$(curl -s "http://$CONFIGURED_IP:8000/" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            print_success "Backend responding - Version: $API_VERSION"
        else
            print_error "Backend not responding"
        fi

        if curl -s "http://$CONFIGURED_IP:3000" > /dev/null; then
            print_success "Frontend responding"
        else
            print_error "Frontend not responding"
        fi

        print_success "Network production deployment complete!"
        echo "🖥️  Frontend: http://$CONFIGURED_IP:3000"
        echo "🔧 Backend: http://$CONFIGURED_IP:8000"

        # Offer to setup users
        echo ""
        echo "Setup initial users? (Y/n): "
        read -r SETUP_USERS
        if [[ ! "$SETUP_USERS" =~ ^[Nn]$ ]]; then
            if [[ -f "$SCRIPT_DIR/setup-users.sh" ]]; then
                "$SCRIPT_DIR/setup-users.sh" --all
            else
                print_warning "setup-users.sh not found, skipping user setup"
            fi
        fi
        ;;

    3)
        print_header "Test Instance Deployment"
        print_info "Deploying test instance on ports 3001/8001..."

        # Check if production is running
        if docker-compose ps | grep -q "networkmapper.*Up"; then
            print_info "Production instance detected - will remain running"
        else
            print_warning "No production instance detected"
        fi

        # Stop existing test
        print_info "Stopping any existing test instance..."
        docker-compose -f docker-compose.test.yml -p networkmapper-test down || true

        # Build test
        print_info "Building test containers..."
        CACHE_BUST=$(date +%s)
        docker-compose -f docker-compose.test.yml -p networkmapper-test build --build-arg CACHE_BUST=$CACHE_BUST

        # Start test
        print_info "Starting test instance..."
        docker-compose -f docker-compose.test.yml -p networkmapper-test up -d

        # Wait for services
        print_info "Waiting for test services..."
        sleep 30

        # Verify test deployment
        if curl -s "http://localhost:8001/health" > /dev/null; then
            print_success "Test backend responding on http://localhost:8001"
        else
            print_error "Test backend not responding"
        fi

        if curl -s "http://localhost:3001" > /dev/null; then
            print_success "Test frontend responding on http://localhost:3001"
        else
            print_error "Test frontend not responding"
        fi

        print_success "Test deployment complete!"
        echo "🧪 Test Frontend: http://localhost:3001"
        echo "🔧 Test Backend: http://localhost:8001"
        echo "🖥️  Production (if running): http://localhost:3000"

        # Offer to create test users
        echo ""
        echo "Create test users? (Y/n): "
        read -r CREATE_USERS
        if [[ ! "$CREATE_USERS" =~ ^[Nn]$ ]]; then
            print_info "Creating test users..."
            docker-compose -f docker-compose.test.yml -p networkmapper-test exec backend python /app/scripts/create_admin_user.py --samples || true
        fi
        ;;

    4)
        print_header "Local Development with SSL"
        print_info "Setting up HTTPS-enabled local development environment..."

        # Check if SSL certificates exist
        if [[ ! -f "ssl/certs/networkmapper.crt" || ! -f "ssl/certs/networkmapper.key" ]]; then
            print_info "SSL certificates not found. Generating self-signed certificates..."
            if [[ -x "scripts/generate-ssl-cert.sh" ]]; then
                ./scripts/generate-ssl-cert.sh -d localhost -s 127.0.0.1
            else
                print_error "SSL certificate generation script not found!"
                exit 1
            fi
        else
            print_info "Using existing SSL certificates"
        fi

        print_info "Cache busting options:"
        echo "1) Quick build (use existing cache)"
        echo "2) Clean build (remove NetworkMapper images only)"
        echo "3) Nuclear build (remove ALL images and cache)"
        echo "Enter choice (1-3): "
        read -r CACHE_CHOICE

        # Stop existing containers
        print_info "Stopping existing containers..."
        docker-compose down --remove-orphans || true

        case $CACHE_CHOICE in
            1)
                print_info "Quick build with existing cache..."
                CACHE_BUST=$(date +%s)
                docker-compose -f docker-compose.yml -f docker-compose.ssl.yml build --build-arg CACHE_BUST=$CACHE_BUST
                ;;
            2)
                print_info "Clean build - removing NetworkMapper images..."
                docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true
                CACHE_BUST=$(date +%s)
                docker-compose -f docker-compose.yml -f docker-compose.ssl.yml build --no-cache --build-arg CACHE_BUST=$CACHE_BUST
                ;;
            3)
                print_info "Nuclear build - removing ALL images and cache..."
                docker system prune -a -f --volumes
                docker builder prune -a -f || true
                CACHE_BUST=$(date +%s%N)
                docker-compose -f docker-compose.yml -f docker-compose.ssl.yml build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST
                ;;
        esac

        print_info "Starting SSL-enabled containers..."
        docker-compose -f docker-compose.yml -f docker-compose.ssl.yml up --force-recreate -d

        print_info "Waiting for services to start..."
        sleep 15

        # Verify deployment
        if curl -k -s "https://localhost/api/v1/health" > /dev/null; then
            print_success "Backend responding on https://localhost/api/v1"
        else
            print_error "Backend not responding"
        fi

        if curl -k -s "https://localhost" > /dev/null; then
            print_success "Frontend responding on https://localhost"
        else
            print_error "Frontend not responding"
        fi

        print_success "SSL-enabled local development deployment complete!"
        echo "🔒 Frontend: https://localhost"
        echo "🔧 Backend: https://localhost/api/v1"
        echo "📊 API Docs: https://localhost/docs"
        print_warning "Your browser will show a security warning for the self-signed certificate."
        print_warning "Click 'Advanced' and 'Proceed to localhost' to continue."
        ;;

    5)
        print_header "Network Production with SSL"

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
        if [[ ! -f "ssl/certs/networkmapper.crt" || ! -f "ssl/certs/networkmapper.key" ]]; then
            CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
            if [[ -z "$CONFIGURED_IP" ]]; then
                CONFIGURED_IP=$(grep "REACT_APP_API_URL=" .env.network | sed 's/.*:\/\/\([^:]*\).*/\1/')
            fi

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

        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        print_info "Deploying SSL production to network IP: $CONFIGURED_IP"

        # Ask about database preservation
        echo "Preserve existing database? (Y/n): "
        read -r PRESERVE_DB

        print_info "Stopping containers..."
        if [[ "$PRESERVE_DB" =~ ^[Nn]$ ]]; then
            docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml down --remove-orphans --volumes
            print_warning "Database will be reset"
        else
            docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml down --remove-orphans
            print_info "Database preserved"
        fi

        print_info "Building and deploying with SSL..."
        CACHE_BUST=$(date +%s%N)
        docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml build --no-cache --build-arg CACHE_BUST=$CACHE_BUST
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

        print_success "SSL network production deployment complete!"
        echo "🔒 Frontend: https://$CONFIGURED_IP"
        echo "🔧 Backend: https://$CONFIGURED_IP/api/v1"
        echo "📊 API Docs: https://$CONFIGURED_IP/docs"
        print_warning "Browsers will show a security warning for the self-signed certificate."
        ;;

    6)
        print_header "Nuclear Clean Rebuild"
        print_warning "THIS WILL REMOVE ALL DOCKER DATA!"
        echo "This will remove:"
        echo "- All containers (running and stopped)"
        echo "- All images (including system images)"
        echo "- All networks (except defaults)"
        echo "- All volumes"
        echo "- All build cache"
        echo ""
        echo "Type 'DELETE EVERYTHING' to confirm: "
        read -r CONFIRM

        if [[ "$CONFIRM" != "DELETE EVERYTHING" ]]; then
            print_info "Operation cancelled"
            exit 0
        fi

        print_warning "Starting nuclear cleanup..."

        # Stop and remove everything
        docker stop $(docker ps -aq) 2>/dev/null || true
        docker rm -f $(docker ps -aq) 2>/dev/null || true
        docker rmi -f $(docker images -aq) 2>/dev/null || true
        docker network rm $(docker network ls -q --filter type=custom) 2>/dev/null || true
        docker volume rm $(docker volume ls -q) 2>/dev/null || true
        docker system prune -a -f --volumes
        docker builder prune -a -f || true

        print_success "Nuclear cleanup complete!"

        # Ask what to rebuild
        echo "What would you like to rebuild?"
        echo "1) Local development"
        echo "2) Network production (.env.network required)"
        echo "3) Dev instance (.env.dev on ports 3001/8001)"
        echo "4) Nothing - just cleaned"
        echo "Enter choice (1-4): "
        read -r REBUILD_CHOICE

        case $REBUILD_CHOICE in
            1)
                print_info "Rebuilding for local development..."
                CACHE_BUST=$(date +%s%N)
                docker-compose build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST
                docker-compose up -d
                print_success "Local rebuild complete!"
                ;;
            2)
                if [[ ! -f ".env.network" ]]; then
                    print_error ".env.network not found!"
                    exit 1
                fi
                print_info "Rebuilding for network production..."
                CACHE_BUST=$(date +%s%N)
                docker-compose --env-file .env.network build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST
                docker-compose --env-file .env.network up -d
                print_success "Network rebuild complete!"
                ;;
            3)
                if [[ ! -f ".env.dev" ]]; then
                    print_error ".env.dev not found!"
                    exit 1
                fi
                print_info "Rebuilding for dev instance..."
                CACHE_BUST=$(date +%s%N)
                docker-compose -f docker-compose.test.yml --env-file .env.dev -p networkmapper-dev build --no-cache --pull --build-arg CACHE_BUST=$CACHE_BUST
                docker-compose -f docker-compose.test.yml --env-file .env.dev -p networkmapper-dev up -d
                print_success "Dev instance rebuild complete!"
                ;;
            4)
                print_info "Cleanup complete - no rebuild performed"
                ;;
        esac
        ;;

    7)
        print_header "Network Fresh Deploy (Ultra-Aggressive)"

        # Check for .env.network
        if [[ ! -f ".env.network" ]]; then
            print_error ".env.network file not found!"
            exit 1
        fi

        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        print_warning "ULTRA-AGGRESSIVE DEPLOYMENT MODE for $CONFIGURED_IP"
        print_info "This will completely rebuild everything from scratch"

        echo "Continue with ultra-aggressive deployment? (y/N): "
        read -r CONFIRM_ULTRA

        if [[ ! "$CONFIRM_ULTRA" =~ ^[Yy]$ ]]; then
            print_info "Operation cancelled"
            exit 0
        fi

        # Ultra-aggressive cleanup
        print_info "Destroying all containers and data..."
        docker-compose --env-file .env.network down --remove-orphans --volumes || true
        docker stop $(docker ps -aq) 2>/dev/null || true
        docker rm -f $(docker ps -aq) 2>/dev/null || true

        print_info "Removing ALL NetworkMapper images..."
        docker images | grep -E "(networkmapper|networkMapper)" | awk '{print $3}' | xargs -r docker rmi -f || true
        docker images | grep -E "frontend|backend" | awk '{print $3}' | xargs -r docker rmi -f || true

        print_info "Nuclear Docker cleanup..."
        docker system prune -a -f --volumes
        docker builder prune -a -f || true
        docker buildx prune -a -f || true

        print_info "Clearing all build caches..."
        rm -rf frontend/node_modules || true
        rm -rf frontend/.next || true
        rm -rf frontend/build || true
        rm -rf backend/__pycache__ || true
        find . -name "*.pyc" -delete || true

        print_info "Invalidating Docker layers..."
        touch frontend/Dockerfile backend/Dockerfile
        sleep 2

        print_info "Ultra cache-bust build..."
        ULTRA_CACHE_BUST=$(date +%s%N)
        docker build --no-cache --pull --build-arg CACHE_BUST=$ULTRA_CACHE_BUST -t networkmapper_frontend:latest frontend/
        docker build --no-cache --pull --build-arg CACHE_BUST=$ULTRA_CACHE_BUST -t networkmapper_backend:latest backend/

        print_info "Starting with force recreate..."
        docker-compose --env-file .env.network up --force-recreate -d

        print_info "Waiting for ultra-fresh deployment..."
        sleep 30

        # Verify ultra deployment
        if curl -s "http://$CONFIGURED_IP:8000/health" > /dev/null; then
            API_VERSION=$(curl -s "http://$CONFIGURED_IP:8000/" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            print_success "Ultra-fresh backend - Version: $API_VERSION"
        else
            print_error "Backend not responding after ultra deployment"
        fi

        if curl -s "http://$CONFIGURED_IP:3000" > /dev/null; then
            print_success "Ultra-fresh frontend responding"
        else
            print_error "Frontend not responding after ultra deployment"
        fi

        print_success "Ultra-aggressive deployment complete!"
        ;;

    *)
        print_error "Invalid choice. Please select 1-5."
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