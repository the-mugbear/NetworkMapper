#!/bin/bash
#
# NetworkMapper Status and Management Script
# Shows status of all instances and provides quick management options
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_header() { echo -e "${CYAN}🔧 $1${NC}"; }

echo "========================================"
echo "       NetworkMapper Status"
echo "========================================"
echo

cd "$PROJECT_ROOT"

# Check production instance
print_header "Production Instance Status"
if docker-compose ps | grep -q "networkmapper.*Up"; then
    print_success "Production instance is running"
    echo "  🖥️  Frontend: http://localhost:3000"
    echo "  🔧 Backend:  http://localhost:8000"
    echo "  📊 API Docs: http://localhost:8000/docs"

    # Check if frontend is responding
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        print_success "Frontend is responding"
    else
        print_warning "Frontend may be starting up..."
    fi

    # Check if backend is responding
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        print_success "Backend is healthy"
    else
        print_warning "Backend may be starting up..."
    fi
else
    print_warning "Production instance is not running"
fi
echo

# Check test instance
print_header "Test Instance Status"
if docker-compose -f docker-compose.test.yml -p networkmapper-test ps | grep -q "Up"; then
    print_success "Test instance is running"
    echo "  🖥️  Frontend: http://localhost:3001"
    echo "  🔧 Backend:  http://localhost:8001"
    echo "  📊 API Docs: http://localhost:8001/docs"

    # Check if test frontend is responding
    if curl -s http://localhost:3001 >/dev/null 2>&1; then
        print_success "Test frontend is responding"
    else
        print_warning "Test frontend may be starting up..."
    fi

    # Check if test backend is responding
    if curl -s http://localhost:8001/health >/dev/null 2>&1; then
        print_success "Test backend is healthy"
    else
        print_warning "Test backend may be starting up..."
    fi
else
    print_warning "Test instance is not running"
fi
echo

# Show available scripts
print_header "Available Management Scripts"
echo "Deployment Scripts:"
echo "  ./scripts/deploy.sh            - Unified deployment script (all options)"
echo
echo "User Management:"
echo "  ./scripts/setup-users.sh       - Create admin and test users"
echo "  ./scripts/setup-users.sh --all - Create admin + sample users"
echo
echo "Maintenance:"
echo "  ./scripts/collect-logs.sh      - Collect comprehensive logs for debugging"
echo "  ./scripts/status.sh            - Show this status (current script)"
echo

# Show quick actions
print_header "Quick Actions"
echo "Production Instance:"
echo "  Start:  docker-compose up -d"
echo "  Stop:   docker-compose down"
echo "  Logs:   docker-compose logs -f"
echo "  Reset:  docker-compose down -v && docker-compose up -d"
echo
echo "Test Instance:"
echo "  Start:  docker-compose -f docker-compose.test.yml -p networkmapper-test up -d"
echo "  Stop:   docker-compose -f docker-compose.test.yml -p networkmapper-test down"
echo "  Logs:   docker-compose -f docker-compose.test.yml -p networkmapper-test logs -f"
echo "  Reset:  docker-compose -f docker-compose.test.yml -p networkmapper-test down -v"
echo

# Show disk usage
print_header "Resource Usage"
echo "Docker containers:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(networkmapper|NAMES)"
echo
echo "Docker volumes:"
docker volume ls | grep -E "(networkmapper|postgres)"
echo

print_info "For detailed logs: ./scripts/collect-logs.sh"
print_info "For all deployments: ./scripts/deploy.sh"