#!/bin/bash

# NetworkMapper Log Collection Script
# Aggregates and collects all logs for troubleshooting

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() { echo -e "${BLUE}📋 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# Create timestamp for the log collection
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="troubleshooting_logs_$TIMESTAMP"

print_info "Starting NetworkMapper log collection..."
print_info "Creating log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"

# System Information
print_info "Collecting system information..."
{
    echo "=== SYSTEM INFORMATION ==="
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "OS: $(uname -a)"
    echo "Docker Version: $(docker --version 2>/dev/null || echo 'Docker not found')"
    echo "Docker Compose Version: $(docker-compose --version 2>/dev/null || echo 'Docker Compose not found')"
    echo "Current Directory: $(pwd)"
    echo "User: $(whoami)"
    echo ""
} > "$LOG_DIR/system_info.txt"

# Network Configuration
print_info "Collecting network configuration..."
{
    echo "=== NETWORK CONFIGURATION ==="
    echo "IP Addresses:"
    ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network info not available"
    echo ""
    echo "Routing Table:"
    ip route show 2>/dev/null || route -n 2>/dev/null || echo "Route info not available"
    echo ""
    echo "DNS Configuration:"
    cat /etc/resolv.conf 2>/dev/null || echo "DNS config not available"
    echo ""
} > "$LOG_DIR/network_info.txt"

# Environment Files
print_info "Collecting environment configuration..."
{
    echo "=== ENVIRONMENT CONFIGURATION ==="
    echo "Contents of .env.network:"
    if [[ -f ".env.network" ]]; then
        cat .env.network
    else
        echo "File not found"
    fi
    echo ""
    echo "Contents of docker-compose.yml:"
    if [[ -f "docker-compose.yml" ]]; then
        cat docker-compose.yml
    else
        echo "File not found"
    fi
    echo ""
} > "$LOG_DIR/environment_config.txt"

# Docker Status
print_info "Collecting Docker container status..."
{
    echo "=== DOCKER CONTAINER STATUS ==="
    echo "Running containers:"
    docker ps 2>/dev/null || echo "Failed to get container status"
    echo ""
    echo "All containers:"
    docker ps -a 2>/dev/null || echo "Failed to get all containers"
    echo ""
    echo "Docker images:"
    docker images 2>/dev/null || echo "Failed to get images"
    echo ""
    echo "Docker networks:"
    docker network ls 2>/dev/null || echo "Failed to get networks"
    echo ""
    echo "Docker volumes:"
    docker volume ls 2>/dev/null || echo "Failed to get volumes"
    echo ""
} > "$LOG_DIR/docker_status.txt"

# Container Logs
print_info "Collecting container logs..."
if docker-compose ps -q > /dev/null 2>&1; then
    # Backend logs
    print_info "Collecting backend logs..."
    {
        echo "=== BACKEND CONTAINER LOGS ==="
        docker-compose logs backend 2>/dev/null || echo "Failed to get backend logs"
    } > "$LOG_DIR/backend_logs.txt"
    
    # Frontend logs
    print_info "Collecting frontend logs..."
    {
        echo "=== FRONTEND CONTAINER LOGS ==="
        docker-compose logs frontend 2>/dev/null || echo "Failed to get frontend logs"
    } > "$LOG_DIR/frontend_logs.txt"
    
    # Database logs
    print_info "Collecting database logs..."
    {
        echo "=== DATABASE CONTAINER LOGS ==="
        docker-compose logs db 2>/dev/null || echo "Failed to get database logs"
    } > "$LOG_DIR/database_logs.txt"
    
    # All container logs combined
    print_info "Collecting combined container logs..."
    {
        echo "=== ALL CONTAINER LOGS COMBINED ==="
        docker-compose logs --timestamps 2>/dev/null || echo "Failed to get combined logs"
    } > "$LOG_DIR/all_container_logs.txt"
else
    print_warning "No docker-compose containers found"
    echo "No docker-compose containers running" > "$LOG_DIR/container_logs_not_available.txt"
fi

# Application Health Checks
print_info "Performing application health checks..."
{
    echo "=== APPLICATION HEALTH CHECKS ==="
    
    # Check if .env.network exists and get configured IP
    if [[ -f ".env.network" ]]; then
        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        echo "Configured IP: $CONFIGURED_IP"
        
        if [[ -n "$CONFIGURED_IP" ]]; then
            echo ""
            echo "Testing Backend API connectivity:"
            if curl -s --max-time 10 "http://$CONFIGURED_IP:8000/health" > /dev/null; then
                echo "✅ Backend API is responding"
                echo "Backend API Response:"
                curl -s --max-time 10 "http://$CONFIGURED_IP:8000/health" 2>/dev/null || echo "Failed to get response"
            else
                echo "❌ Backend API is not responding"
            fi
            
            echo ""
            echo "Testing Frontend connectivity:"
            if curl -s --max-time 10 "http://$CONFIGURED_IP:3000" > /dev/null; then
                echo "✅ Frontend is responding"
            else
                echo "❌ Frontend is not responding"
            fi
            
            echo ""
            echo "Testing CORS preflight:"
            HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS \
                -H "Origin: http://$CONFIGURED_IP:3000" \
                -H "Access-Control-Request-Method: GET" \
                -H "Access-Control-Request-Headers: Content-Type" \
                --max-time 10 \
                "http://$CONFIGURED_IP:8000/api/v1/dashboard/stats" 2>/dev/null || echo "000")
            
            if [[ "$HTTP_STATUS" == "200" ]]; then
                echo "✅ CORS preflight successful"
            else
                echo "❌ CORS preflight failed (HTTP $HTTP_STATUS)"
            fi
        else
            echo "No HOST_IP found in .env.network"
        fi
    else
        echo "No .env.network file found"
    fi
    
    echo ""
    echo "Port connectivity tests:"
    for port in 3000 8000; do
        if ss -tln | grep ":$port " > /dev/null 2>&1; then
            echo "✅ Port $port is listening"
        else
            echo "❌ Port $port is not listening"
        fi
    done
} > "$LOG_DIR/health_checks.txt"

# Recent Git History
print_info "Collecting Git information..."
{
    echo "=== GIT REPOSITORY INFORMATION ==="
    echo "Current branch:"
    git branch --show-current 2>/dev/null || echo "Not a git repository"
    echo ""
    echo "Recent commits (last 10):"
    git log --oneline -10 2>/dev/null || echo "No git history available"
    echo ""
    echo "Git status:"
    git status 2>/dev/null || echo "Not a git repository"
    echo ""
    echo "Uncommitted changes:"
    git diff --name-only 2>/dev/null || echo "No git repository or no changes"
} > "$LOG_DIR/git_info.txt"

# File System Information
print_info "Collecting file system information..."
{
    echo "=== FILE SYSTEM INFORMATION ==="
    echo "Current directory contents:"
    ls -la
    echo ""
    echo "Disk space:"
    df -h . 2>/dev/null || echo "Disk info not available"
    echo ""
    echo "Key file sizes:"
    if [[ -f "docker-compose.yml" ]]; then
        echo "docker-compose.yml: $(wc -l < docker-compose.yml) lines"
    fi
    if [[ -d "uploads" ]]; then
        echo "Uploads directory: $(ls uploads/ 2>/dev/null | wc -l) files"
        echo "Upload sizes:"
        du -sh uploads/* 2>/dev/null | head -10 || echo "No uploads"
    fi
} > "$LOG_DIR/filesystem_info.txt"

# Error Patterns Analysis
print_info "Analyzing error patterns..."
{
    echo "=== ERROR PATTERN ANALYSIS ==="
    echo "Recent errors in backend logs:"
    if [[ -f "$LOG_DIR/backend_logs.txt" ]]; then
        grep -i "error\|exception\|traceback\|failed" "$LOG_DIR/backend_logs.txt" | tail -20 || echo "No errors found"
    else
        echo "Backend logs not available"
    fi
    
    echo ""
    echo "Recent CORS-related issues:"
    if [[ -f "$LOG_DIR/all_container_logs.txt" ]]; then
        grep -i "cors\|origin\|access-control" "$LOG_DIR/all_container_logs.txt" | tail -10 || echo "No CORS issues found"
    else
        echo "Container logs not available"
    fi
    
    echo ""
    echo "Database connection issues:"
    if [[ -f "$LOG_DIR/backend_logs.txt" ]]; then
        grep -i "database\|postgres\|connection" "$LOG_DIR/backend_logs.txt" | tail -10 || echo "No database issues found"
    else
        echo "Backend logs not available"
    fi
} > "$LOG_DIR/error_analysis.txt"

# Authentication and Audit Logs
print_info "Collecting authentication and audit logs..."
{
    echo "=== AUTHENTICATION AND AUDIT LOGS ==="
    echo "Frontend Browser Logs (if available):"
    # Try to extract authentication logs from browser developer tools if running
    if docker-compose ps frontend > /dev/null 2>&1; then
        echo "Frontend authentication logging is instrumented - check browser console for:"
        echo "- AUTH category logs"
        echo "- LOGIN_ATTEMPT, LOGIN_SUCCESS, LOGIN_FAILED audit events"
        echo "- PROTECTED_ROUTE access decisions"
        echo "- Authentication state changes"
        echo ""
    fi

    echo "Backend Authentication Logs:"
    if [[ -f "$LOG_DIR/backend_logs.txt" ]]; then
        grep -i "auth\|login\|token\|password\|audit\|bcrypt\|jwt" "$LOG_DIR/backend_logs.txt" | tail -30 || echo "No authentication events found"
    else
        echo "Backend logs not available"
    fi

    echo ""
    echo "Audit Endpoint Activity:"
    if [[ -f "$LOG_DIR/backend_logs.txt" ]]; then
        grep -i "audit.*log\|/api/v1/audit" "$LOG_DIR/backend_logs.txt" | tail -20 || echo "No audit endpoint activity found"
    else
        echo "Backend logs not available"
    fi

    echo ""
    echo "Authentication Errors:"
    if [[ -f "$LOG_DIR/backend_logs.txt" ]]; then
        grep -i "401\|unauthorized\|forbidden\|invalid.*password\|bcrypt.*error" "$LOG_DIR/backend_logs.txt" | tail -20 || echo "No authentication errors found"
    else
        echo "Backend logs not available"
    fi
} > "$LOG_DIR/auth_audit_logs.txt"

# Browser Storage Information
print_info "Collecting browser storage information..."
{
    echo "=== BROWSER STORAGE ANALYSIS ==="
    echo "This log collection cannot directly access browser storage, but here's what to check:"
    echo ""
    echo "LocalStorage Keys to Examine:"
    echo "- auth_token: JWT token for API authentication"
    echo "- auth_user: Serialized user object with role information"
    echo ""
    echo "SessionStorage Keys to Examine:"
    echo "- debug_session_id: Logging session identifier"
    echo ""
    echo "Browser Console Commands for Manual Debugging:"
    echo "// Check authentication state"
    echo "console.log('Auth Token:', localStorage.getItem('auth_token'));"
    echo "console.log('Auth User:', localStorage.getItem('auth_user'));"
    echo "console.log('Session ID:', sessionStorage.getItem('debug_session_id'));"
    echo ""
    echo "// Export authentication logs (if logger is available)"
    echo "if (window.logger) { console.log(logger.getAuthLogs()); }"
    echo ""
    echo "// Check comprehensive logs"
    echo "if (window.logger) { console.log(logger.exportLogs()); }"
} > "$LOG_DIR/browser_storage_info.txt"

# Create summary file
print_info "Creating troubleshooting summary..."
{
    echo "=== TROUBLESHOOTING SUMMARY ==="
    echo "Generated: $(date)"
    echo "NetworkMapper Version: Backend 1.2.1, Frontend 1.4.1"
    echo "Authentication System: JWT with comprehensive logging"
    echo ""
    
    # Quick health summary
    if [[ -f ".env.network" ]]; then
        CONFIGURED_IP=$(grep "^HOST_IP=" .env.network | cut -d'=' -f2)
        echo "Configured for network deployment on: $CONFIGURED_IP"
    else
        echo "Not configured for network deployment"
    fi
    
    echo ""
    echo "Container Status:"
    docker-compose ps 2>/dev/null | grep -E "(Up|Exited|Dead)" || echo "No containers found"
    
    echo ""
    echo "Files collected in this troubleshooting package:"
    echo "- system_info.txt: System and software versions"
    echo "- network_info.txt: Network configuration and connectivity"
    echo "- environment_config.txt: Environment and Docker configuration"
    echo "- docker_status.txt: Docker container, image, and network status"
    echo "- backend_logs.txt: Backend application logs"
    echo "- frontend_logs.txt: Frontend application logs"
    echo "- database_logs.txt: Database logs"
    echo "- all_container_logs.txt: Combined timestamped logs"
    echo "- health_checks.txt: Application connectivity and health tests"
    echo "- git_info.txt: Repository status and recent changes"
    echo "- filesystem_info.txt: File system and directory information"
    echo "- error_analysis.txt: Error pattern analysis"
    echo "- auth_audit_logs.txt: Authentication and audit event logs"
    echo "- browser_storage_info.txt: Browser storage debugging guide"
    echo ""
    echo "To share these logs:"
    echo "1. Review the files for any sensitive information"
    echo "2. Create archive: tar -czf ${LOG_DIR}.tar.gz $LOG_DIR"
    echo "3. Share the archive file for troubleshooting"
} > "$LOG_DIR/README.txt"

# Create compressed archive
print_info "Creating compressed archive..."
tar -czf "${LOG_DIR}.tar.gz" "$LOG_DIR" 2>/dev/null

# Final output
echo ""
print_success "Log collection completed!"
echo ""
print_info "Troubleshooting package created:"
echo "📁 Directory: $LOG_DIR"
echo "📦 Archive: ${LOG_DIR}.tar.gz"
echo ""
print_info "Package contents:"
ls -la "$LOG_DIR"
echo ""
print_warning "Please review logs for sensitive information before sharing!"
echo ""
print_info "To view the summary: cat $LOG_DIR/README.txt"
print_info "To extract archive: tar -xzf ${LOG_DIR}.tar.gz"
echo ""