#!/usr/bin/env python3

import sys
import os
import re
from datetime import datetime

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def test_gnmap_parsing():
    """Test .gnmap parser logic without database dependencies"""
    
    # Read the sample file
    with open('sample_gnmap.gnmap', 'r') as f:
        content = f.read()
    
    lines = content.strip().split('\n')
    print(f"📁 Loaded {len(lines)} lines from sample_gnmap.gnmap")
    print("=" * 60)
    
    # Test scan info extraction
    print("🔍 SCAN INFO EXTRACTION:")
    scan_info = extract_scan_info(lines)
    for key, value in scan_info.items():
        print(f"  {key}: {value}")
    print()
    
    # Test host parsing
    print("🖥️  HOST PARSING:")
    hosts_data = parse_hosts(lines)
    print(f"Found {len(hosts_data)} hosts")
    print()
    
    # Show detailed parsing for each host
    for i, host in enumerate(hosts_data, 1):
        print(f"Host {i}: {host['ip_address']}")
        if host.get('hostname'):
            print(f"  Hostname: {host['hostname']}")
        print(f"  State: {host['state']}")
        print(f"  Ports: {len(host.get('ports', []))}")
        
        # Show all ports for the first host, first 5 for others
        max_ports = len(host.get('ports', [])) if i == 4 else 5  # Show all for last host
        
        for port in host.get('ports', [])[:max_ports]:
            service_info = f" ({port.get('service_name', 'unknown')})" if port.get('service_name') else ""
            version_info = f" - {port.get('service_version')}" if port.get('service_version') else ""
            print(f"    {port['port_number']}/{port['protocol']} {port['state']}{service_info}{version_info}")
        
        if len(host.get('ports', [])) > max_ports:
            print(f"    ... and {len(host['ports']) - max_ports} more ports")
        print()

def extract_scan_info(lines):
    """Extract scan metadata from .gnmap file header and footer"""
    scan_info = {}
    
    for line in lines:
        line = line.strip()
        
        # Parse command line from first comment
        if line.startswith('Nmap') and 'command' not in scan_info:
            # Extract version
            match = re.search(r'Nmap (\S+)', line)
            if match:
                scan_info['version'] = match.group(1)
                
            # Extract command
            cmd_match = re.search(r'Nmap .+? as: (.+)', line)
            if cmd_match:
                scan_info['command'] = cmd_match.group(1)
        
        # Parse start time
        if 'scan initiated' in line:
            time_match = re.search(r'scan initiated (.+)$', line)
            if time_match:
                try:
                    scan_info['start_time'] = datetime.strptime(time_match.group(1), '%a %b %d %H:%M:%S %Y')
                except ValueError:
                    scan_info['start_time'] = time_match.group(1)
        
        # Parse end time
        if 'done at' in line:
            time_match = re.search(r'done at (.+);', line)
            if time_match:
                try:
                    scan_info['end_time'] = datetime.strptime(time_match.group(1), '%a %b %d %H:%M:%S %Y')
                except ValueError:
                    scan_info['end_time'] = time_match.group(1)
    
    return scan_info

def parse_hosts(lines):
    """Parse host data from .gnmap lines"""
    hosts_data = {}  # Use dict to merge status and port lines by IP
    
    for line in lines:
        line = line.strip()
        
        # Skip comments and empty lines
        if line.startswith('#') or not line or line.startswith('Nmap') or line.startswith('Ports scanned'):
            continue
            
        # Parse Host lines
        if line.startswith('Host:'):
            host_data = parse_host_line(line)
            if host_data:
                ip = host_data['ip_address']
                
                # Merge with existing host data or create new
                if ip in hosts_data:
                    # Merge data - prefer non-empty values
                    existing = hosts_data[ip]
                    existing['hostname'] = existing.get('hostname') or host_data.get('hostname')
                    # Prefer actual state over 'unknown'
                    if host_data.get('state') and host_data['state'] != 'unknown':
                        existing['state'] = host_data['state']
                    elif not existing.get('state') or existing['state'] == 'unknown':
                        existing['state'] = host_data.get('state', 'unknown')
                    if host_data.get('ports'):
                        existing['ports'] = host_data['ports']
                else:
                    hosts_data[ip] = host_data
    
    # Convert dict back to list and filter out down hosts with no ports
    result = []
    for host_data in hosts_data.values():
        # Only include hosts that are up or have port data
        if host_data.get('state') == 'up' or host_data.get('ports'):
            result.append(host_data)
    
    return result

def parse_host_line(line):
    """Parse a single Host: line from .gnmap format"""
    try:
        # .gnmap format: Host: <ip> (<hostname>)	Status: <state>	Ports: <port_info>
        parts = line.split('\t')
        
        if len(parts) < 2:
            return None
        
        # Parse host info (first part)
        host_part = parts[0]  # "Host: 192.168.1.1 (hostname)"
        host_match = re.match(r'Host:\s+([^\s]+)(?:\s+\(([^)]+)\))?', host_part)
        
        if not host_match:
            return None
            
        ip_address = host_match.group(1)
        hostname = host_match.group(2) if host_match.group(2) and host_match.group(2).strip() else None
        
        # Parse status
        state = 'unknown'
        for part in parts:
            if part.startswith('Status:'):
                status_match = re.search(r'Status:\s+(\w+)', part)
                if status_match:
                    state = status_match.group(1).lower()
        
        # Parse ports
        ports_data = []
        for part in parts:
            if part.startswith('Ports:'):
                ports_info = part[6:].strip()  # Remove "Ports:"
                if ports_info:
                    ports_data = parse_ports_info(ports_info)
        
        # Don't skip here - let the merge logic handle filtering
        
        return {
            'ip_address': ip_address,
            'hostname': hostname,
            'state': state,
            'ports': ports_data
        }
        
    except Exception as e:
        print(f"⚠️  Failed to parse host line: {line[:100]}... Error: {str(e)}")
        return None

def parse_ports_info(ports_info):
    """Parse port information from .gnmap format"""
    ports_data = []
    
    # .gnmap ports format: port/state/protocol/owner/service/rpc/version, port/state/...
    if not ports_info or ports_info.strip() == '':
        return ports_data
        
    port_entries = ports_info.split(', ')
    
    for entry in port_entries:
        try:
            # Split by / - format: port/state/protocol/owner/service/rpc/version
            fields = entry.split('/')
            if len(fields) < 3:
                continue
                
            port_number = int(fields[0])
            state = fields[1]
            protocol = fields[2]
            
            # Extract additional service info if available
            service_name = fields[4] if len(fields) > 4 and fields[4] else None
            service_version = fields[6] if len(fields) > 6 and fields[6] else None
            
            port_data = {
                'port_number': port_number,
                'protocol': protocol,
                'state': state,
                'service_name': service_name,
                'service_version': service_version
            }
            ports_data.append(port_data)
                
        except (ValueError, IndexError) as e:
            print(f"⚠️  Failed to parse port entry: {entry} - {str(e)}")
            continue
    
    return ports_data

if __name__ == "__main__":
    test_gnmap_parsing()