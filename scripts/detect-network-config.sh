#!/bin/bash

# NetworkMapper Dynamic Network Configuration Detection Script
# Automatically detects the best network interface and IP for production deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output (to stderr to avoid mixing with function returns)
print_info() { echo -e "${BLUE}ℹ️  $1${NC}" >&2; }
print_success() { echo -e "${GREEN}✅ $1${NC}" >&2; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}" >&2; }
print_error() { echo -e "${RED}❌ $1${NC}" >&2; }

# Function to detect the best network interface
detect_network_interface() {
    print_info "Detecting network interfaces..."
    
    # Method 1: Try to get IP from default route
    local default_ip
    default_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP '(?<=src\s)\d+(\.\d+){3}' | head -1)
    if validate_ip "$default_ip"; then
        print_info "Using IP from default route: $default_ip"
        echo "$default_ip"
        return 0
    fi
    
    # Method 2: Get primary interface from default route
    local primary_interface
    primary_interface=$(ip route | grep '^default' | awk '{print $5}' | head -1)
    if [[ -n "$primary_interface" ]]; then
        local interface_ip
        interface_ip=$(ip -4 addr show "$primary_interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
        if validate_ip "$interface_ip"; then
            print_info "Using IP from primary interface ($primary_interface): $interface_ip"
            echo "$interface_ip"
            return 0
        fi
    fi
    
    # Method 3: Use hostname -I (most reliable fallback)
    local hostname_ip
    hostname_ip=$(hostname -I | awk '{print $1}')
    if validate_ip "$hostname_ip" && [[ "$hostname_ip" != "127.0.0.1" ]]; then
        print_info "Using IP from hostname: $hostname_ip"
        echo "$hostname_ip"
        return 0
    fi
    
    # Method 4: Get first non-loopback IP from all interfaces
    local first_ip
    first_ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
    if validate_ip "$first_ip"; then
        print_warning "Using first available IP: $first_ip"
        echo "$first_ip"
        return 0
    fi
    
    # Method failed
    return 1
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Function to test network connectivity
test_connectivity() {
    local ip=$1
    print_info "Testing network connectivity for $ip..."
    
    # Test if we can bind to the IP (basic check)
    if command -v nc >/dev/null 2>&1; then
        if timeout 2 nc -l -p 0 -s "$ip" 2>/dev/null; then
            print_success "IP $ip is bindable and accessible"
            return 0
        fi
    fi
    
    # Alternative test: check if IP is assigned to an interface
    if ip addr show | grep -q "inet $ip/"; then
        print_success "IP $ip is assigned to a network interface"
        return 0
    fi
    
    print_warning "Could not verify connectivity for $ip, but proceeding anyway"
    return 0
}

# Function to detect if we're in a Docker environment
detect_docker_environment() {
    if [ -f /.dockerenv ] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    return 1
}

# Function to get the primary gateway IP for Docker environments
get_docker_host_ip() {
    # In Docker, try to get the host IP from the default gateway
    local gateway_ip
    gateway_ip=$(ip route | grep '^default' | awk '{print $3}' | head -1)
    
    if validate_ip "$gateway_ip"; then
        # Try to get the Docker host IP by checking the bridge network
        local host_ip
        host_ip=$(ip route get "$gateway_ip" 2>/dev/null | grep -oP '(?<=src\s)\d+(\.\d+){3}' | head -1)
        
        if validate_ip "$host_ip"; then
            echo "$host_ip"
            return 0
        fi
    fi
    
    # Fallback to standard detection
    detect_network_interface
}

# Main function
main() {
    print_info "NetworkMapper Dynamic Network Configuration Detection"
    print_info "=================================================="
    
    # Detect environment
    local is_docker=false
    if detect_docker_environment; then
        print_info "Docker environment detected"
        is_docker=true
    fi
    
    # Detect IP address
    local detected_ip=""
    if [ "$is_docker" = true ]; then
        detected_ip=$(get_docker_host_ip)
    else
        detected_ip=$(detect_network_interface)
    fi
    
    # Debug output
    print_info "Raw detected IP: '$detected_ip'"
    
    # Validate detected IP
    if [[ -z "$detected_ip" ]] || ! validate_ip "$detected_ip"; then
        print_error "Could not detect a valid IP address (detected: '$detected_ip')"
        print_info "Please check your network configuration"
        exit 1
    fi
    
    print_success "Detected IP address: $detected_ip"
    
    # Test connectivity
    test_connectivity "$detected_ip"
    
    # Generate network configuration
    local config_file=".env.network"
    print_info "Generating network configuration: $config_file"
    
    cat > "$config_file" << EOF
# Network configuration for external access
# Auto-generated on $(date)
HOST_IP=$detected_ip

# Frontend will connect to this backend URL
REACT_APP_API_URL=http://$detected_ip:8000

# Backend will allow CORS from these origins
CORS_ORIGINS=http://localhost:3000,http://$detected_ip:3000
EOF
    
    print_success "Generated network configuration:"
    print_info "HOST_IP=$detected_ip"
    print_info "REACT_APP_API_URL=http://$detected_ip:8000"
    print_info "CORS_ORIGINS=http://localhost:3000,http://$detected_ip:3000"
    
    # Show additional network information
    echo ""
    print_info "Network Interface Information:"
    ip -4 addr show | grep -E '^[0-9]+:|\sinet\s' | grep -v '127.0.0.1' | while read -r line; do
        echo "  $line"
    done
    
    echo ""
    print_info "Routes:"
    ip route | head -5 | while read -r line; do
        echo "  $line"
    done
    
    echo ""
    print_success "Network configuration complete!"
    print_info "You can now run: ./setup-network.sh"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi