#!/bin/bash
#
# User Setup Script for NetworkMapper Security Platform
# Creates initial admin user and optional sample users for testing
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# Function to check if backend is running
check_backend() {
    print_info "Checking if backend is running..."

    if ! ${COMPOSE_CMD} ps backend | grep -q "Up"; then
        print_warning "Backend container is not running. Starting services..."
        cd "$PROJECT_ROOT"
        ${COMPOSE_CMD} up -d backend db

        print_info "Waiting for backend to be ready..."
        sleep 10

        # Wait for backend health check
        for i in {1..30}; do
            if curl -s ${BACKEND_URL}/health >/dev/null 2>&1; then
                print_success "Backend is ready!"
                break
            fi

            if [ $i -eq 30 ]; then
                print_error "Backend failed to start after 30 attempts"
                exit 1
            fi

            echo -n "."
            sleep 2
        done
        echo
    else
        print_success "Backend is already running"
    fi
}

# Function to create admin user
create_admin_user() {
    print_info "Creating admin user..."

    cd "$PROJECT_ROOT"
    ${COMPOSE_CMD} exec -T backend python /app/scripts/create_admin_user.py

    if [ $? -eq 0 ]; then
        print_success "Admin user creation completed"
    else
        print_error "Failed to create admin user"
        exit 1
    fi
}

# Function to create sample users
create_sample_users() {
    print_info "Creating sample users for testing..."

    cd "$PROJECT_ROOT"
    ${COMPOSE_CMD} exec -T backend python /app/scripts/create_admin_user.py --samples

    if [ $? -eq 0 ]; then
        print_success "Sample users created successfully"
        echo
        print_info "Test credentials created:"
        echo "  analyst1  / AnalystPassword123!  (ANALYST)"
        echo "  viewer1   / ViewerPassword123!   (VIEWER)"
        echo "  auditor1  / AuditorPassword123!  (AUDITOR)"
        echo
    else
        print_error "Failed to create sample users"
        exit 1
    fi
}

# Function to show usage
show_usage() {
    echo "NetworkMapper User Setup Script"
    echo "====================================="
    echo
    echo "Usage: $0 [INSTANCE] [OPTIONS]"
    echo
    echo "Instance Types:"
    echo "  --prod          Use production instance (port 3000/8000)"
    echo "  --dev           Use dev instance (port 3001/8001)"
    echo "  --test          Use test instance (port 3001/8001)"
    echo
    echo "Options:"
    echo "  --admin-only    Create only admin user (interactive)"
    echo "  --samples-only  Create only sample test users"
    echo "  --all          Create admin user + sample users"
    echo "  --help         Show this help message"
    echo
    echo "Default behavior: Production instance with interactive admin user creation"
    echo
    echo "Examples:"
    echo "  $0                       # Production, interactive admin creation"
    echo "  $0 --dev --all           # Dev instance, admin + test users"
    echo "  $0 --test --samples-only # Test instance, test users only"
    echo
}

# Main script logic
main() {
    echo "========================================"
    echo "  NetworkMapper User Setup Script"
    echo "========================================"
    echo

    # Set default instance configuration
    INSTANCE_TYPE="prod"
    COMPOSE_CMD="docker-compose"
    BACKEND_URL="http://localhost:8000"
    FRONTEND_URL="http://localhost:3000"

    # Parse instance type first
    case "${1:-}" in
        --prod)
            INSTANCE_TYPE="prod"
            COMPOSE_CMD="docker-compose"
            BACKEND_URL="http://localhost:8000"
            FRONTEND_URL="http://localhost:3000"
            shift
            ;;
        --dev)
            INSTANCE_TYPE="dev"
            COMPOSE_CMD="docker-compose -f docker-compose.test.yml --env-file .env.dev -p networkmapper-dev"
            BACKEND_URL="http://localhost:8001"
            FRONTEND_URL="http://localhost:3001"
            shift
            ;;
        --test)
            INSTANCE_TYPE="test"
            COMPOSE_CMD="docker-compose -f docker-compose.test.yml -p networkmapper-test"
            BACKEND_URL="http://localhost:8001"
            FRONTEND_URL="http://localhost:3001"
            shift
            ;;
    esac

    print_info "Using ${INSTANCE_TYPE} instance (${FRONTEND_URL})"
    echo

    # Parse action options
    case "${1:-}" in
        --help|-h)
            show_usage
            exit 0
            ;;
        --admin-only)
            check_backend
            create_admin_user
            ;;
        --samples-only)
            check_backend
            create_sample_users
            ;;
        --all)
            check_backend
            print_info "Creating admin user and sample users..."
            echo
            create_admin_user
            echo
            create_sample_users
            ;;
        "")
            # Default: interactive admin creation
            check_backend
            create_admin_user
            ;;
        *)
            print_error "Unknown option: $1"
            echo
            show_usage
            exit 1
            ;;
    esac

    echo
    print_success "User setup completed!"
    print_info "You can now access NetworkMapper at: ${FRONTEND_URL}"
    echo
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi