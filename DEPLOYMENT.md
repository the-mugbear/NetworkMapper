# NetworkMapper Deployment Guide

This guide provides comprehensive instructions for deploying NetworkMapper in various environments, including SSL/TLS configuration with self-signed certificates.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Environment Options](#environment-options)
3. [SSL/TLS Configuration](#ssltls-configuration)
4. [Production Deployment](#production-deployment)
5. [Network Deployment](#network-deployment)
6. [Security Considerations](#security-considerations)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Git (for version information)
- 4GB+ RAM recommended
- 20GB+ disk space

### Basic Local Development

```bash
# Clone the repository
git clone <repository-url>
cd NetworkMapper

# Start local development instance
./scripts/deploy.sh
# Select option 1: Local Development

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Documentation: http://localhost:8000/docs
```

## Environment Options

NetworkMapper supports multiple deployment configurations:

### 1. Local Development
- **Ports**: Frontend (3000), Backend (8000), Database (5432)
- **Purpose**: Development and testing
- **Configuration**: Default docker-compose.yml

### 2. Test Instance
- **Ports**: Frontend (3001), Backend (8001), Database (5433)
- **Purpose**: Parallel testing alongside production
- **Configuration**: docker-compose.test.yml

### 3. Network Production
- **Ports**: Frontend (3000), Backend (8000), Database (5432)
- **Purpose**: Production deployment on specific network
- **Configuration**: Uses .env.network file

## SSL/TLS Configuration

### Generating Self-Signed Certificates

For secure HTTPS deployment, you can generate self-signed certificates:

#### Step 1: Create Certificate Directory

```bash
# Create SSL directory
mkdir -p ssl/certs
cd ssl/certs
```

#### Step 2: Generate Private Key

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out networkmapper.key 2048

# Or generate 4096-bit key for enhanced security
openssl genrsa -out networkmapper.key 4096
```

#### Step 3: Create Certificate Signing Request (CSR)

```bash
# Create CSR with interactive prompts
openssl req -new -key networkmapper.key -out networkmapper.csr

# Or create CSR with predefined values
openssl req -new -key networkmapper.key -out networkmapper.csr -subj "/C=US/ST=State/L=City/O=Organization/OU=IT Department/CN=networkmapper.local"
```

**CSR Information Guide:**
- **Country Name (C)**: Two-letter country code (e.g., US, UK, CA)
- **State (ST)**: Full state or province name
- **City (L)**: City or locality name
- **Organization (O)**: Company or organization name
- **Organizational Unit (OU)**: Department name (e.g., IT Department)
- **Common Name (CN)**: Server hostname (e.g., networkmapper.local, 192.168.1.100)

#### Step 4: Generate Self-Signed Certificate

```bash
# Generate certificate valid for 365 days
openssl x509 -req -days 365 -in networkmapper.csr -signkey networkmapper.key -out networkmapper.crt

# Generate certificate with Subject Alternative Names (SAN)
openssl x509 -req -days 365 -in networkmapper.csr -signkey networkmapper.key -out networkmapper.crt \
  -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = networkmapper.local
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 192.168.1.100
EOF
)
```

#### Step 5: Verify Certificate

```bash
# Check certificate details
openssl x509 -in networkmapper.crt -text -noout

# Verify certificate against private key
openssl x509 -noout -modulus -in networkmapper.crt | openssl md5
openssl rsa -noout -modulus -in networkmapper.key | openssl md5
# The MD5 hashes should match
```

#### Step 6: Set Proper Permissions

```bash
# Secure the private key
chmod 600 networkmapper.key
chmod 644 networkmapper.crt

# Change ownership to appropriate user (if needed)
sudo chown root:root networkmapper.key networkmapper.crt
```

### SSL-Enabled Docker Configuration

Create an SSL-enabled nginx configuration:

#### Step 1: Create SSL Nginx Configuration

```bash
# Create ssl-nginx.conf
cat > ssl-nginx.conf << 'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/networkmapper.crt;
    ssl_certificate_key /etc/ssl/private/networkmapper.key;

    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Serve React App
    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;

        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # Proxy API requests to backend
    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # Handle WebSocket connections (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
```

#### Step 2: Create SSL Docker Compose Override

```yaml
# docker-compose.ssl.yml
version: '3.8'

services:
  frontend:
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./ssl/certs/networkmapper.crt:/etc/ssl/certs/networkmapper.crt:ro
      - ./ssl/certs/networkmapper.key:/etc/ssl/private/networkmapper.key:ro
      - ./ssl-nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

#### Step 3: Deploy with SSL

```bash
# Deploy with SSL configuration
docker-compose -f docker-compose.yml -f docker-compose.ssl.yml up -d

# Access via HTTPS
# https://localhost
# https://your-server-ip
```

## Production Deployment

### Environment Configuration

#### Step 1: Create Production Environment File

```bash
# Create .env.network
cat > .env.network << 'EOF'
# Network Configuration
REACT_APP_API_URL=https://your-server-ip:8000
CORS_ORIGINS=https://your-server-ip:3000,https://your-domain.com

# Database Configuration
POSTGRES_DB=networkMapper
POSTGRES_USER=nmapuser
POSTGRES_PASSWORD=your-secure-password-here

# Security Settings
DATABASE_URL=postgresql://nmapuser:your-secure-password-here@db:5432/networkMapper

# Optional: Custom DNS for enrichment
DNS_SERVER=8.8.8.8
EOF
```

#### Step 2: Secure Permissions

```bash
# Secure environment file
chmod 600 .env.network
```

### Production Deployment with SSL

```bash
# Deploy production instance with SSL
docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml up -d

# Verify deployment
docker-compose ps
```

### Create Admin User

```bash
# Create initial admin user
./scripts/setup-users.sh --prod

# Follow prompts to create admin account
```

## Network Deployment

For deployment on a specific network (e.g., 192.168.7.245):

### Step 1: Configure Network Settings

```bash
# Update .env.network for your network
cat > .env.network << 'EOF'
REACT_APP_API_URL=https://192.168.7.245:8000
CORS_ORIGINS=https://192.168.7.245:3000,https://192.168.7.245

# Use your network IP
POSTGRES_DB=networkMapper
POSTGRES_USER=nmapuser
POSTGRES_PASSWORD=your-secure-password-here
DATABASE_URL=postgresql://nmapuser:your-secure-password-here@db:5432/networkMapper
EOF
```

### Step 2: Generate Network-Specific Certificate

```bash
# Generate certificate for specific IP
cd ssl/certs
openssl req -new -key networkmapper.key -out networkmapper.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=192.168.7.245"

# Generate certificate with network IP
openssl x509 -req -days 365 -in networkmapper.csr -signkey networkmapper.key -out networkmapper.crt \
  -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = networkmapper.local
IP.1 = 192.168.7.245
IP.2 = 127.0.0.1
EOF
)
```

### Step 3: Deploy

```bash
# Deploy on network with SSL
./scripts/deploy.sh
# Select option 2: Network Production (SSL)
```

## Security Considerations

### Certificate Management

1. **Self-Signed Certificates**:
   - Browsers will show security warnings
   - Users must manually accept the certificate
   - Not suitable for public-facing production

2. **Production Recommendations**:
   - Use Let's Encrypt for valid certificates
   - Implement certificate rotation
   - Monitor certificate expiration

### Firewall Configuration

```bash
# Example UFW rules
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (redirects to HTTPS)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8000/tcp  # Backend API (if exposed)
sudo ufw enable
```

### Database Security

```bash
# Change default database password
# Update .env.network with strong password
POSTGRES_PASSWORD=$(openssl rand -base64 32)
```

### Application Security

1. **Change Default Credentials**: Update admin passwords immediately
2. **Enable Audit Logging**: Review authentication logs regularly
3. **Network Segmentation**: Deploy in isolated network segments
4. **Regular Updates**: Keep Docker images and dependencies updated

## Troubleshooting

### SSL Certificate Issues

```bash
# Test certificate
openssl s_client -connect localhost:443 -servername localhost

# Check certificate expiration
openssl x509 -in ssl/certs/networkmapper.crt -noout -dates

# Verify private key matches certificate
diff <(openssl x509 -noout -modulus -in ssl/certs/networkmapper.crt | openssl md5) \
     <(openssl rsa -noout -modulus -in ssl/certs/networkmapper.key | openssl md5)
```

### Container Health Checks

```bash
# Check container status
docker-compose ps

# View container logs
docker-compose logs frontend
docker-compose logs backend
docker-compose logs db

# Test backend health
curl -k https://localhost/api/v1/health

# Test frontend
curl -k https://localhost
```

### Network Connectivity

```bash
# Test internal container communication
docker-compose exec frontend ping backend
docker-compose exec backend ping db

# Check port availability
netstat -tulpn | grep -E ':(80|443|3000|8000|5432)'
```

### Log Collection

```bash
# Comprehensive log collection
./scripts/collect-logs.sh

# This creates a timestamped directory with:
# - Container logs
# - System information
# - Network configuration
# - Health check results
# - Authentication logs
```

### Common Issues

1. **Certificate Browser Warnings**:
   - Add certificate to browser trust store
   - Use `--ignore-certificate-errors` for testing

2. **CORS Errors**:
   - Verify CORS_ORIGINS in .env.network
   - Check REACT_APP_API_URL configuration

3. **Database Connection Issues**:
   - Verify DATABASE_URL format
   - Check database container health
   - Ensure proper wait conditions

4. **Port Conflicts**:
   - Check for existing services on ports 80, 443, 3000, 8000
   - Use alternative ports if needed

## Maintenance

### Certificate Renewal

```bash
# Check certificate expiration (90 days warning)
openssl x509 -in ssl/certs/networkmapper.crt -noout -checkend 7776000

# Renew certificate (regenerate with same settings)
cd ssl/certs
openssl x509 -req -days 365 -in networkmapper.csr -signkey networkmapper.key -out networkmapper.crt

# Restart containers to apply new certificate
docker-compose restart frontend
```

### Backup

```bash
# Backup database
docker-compose exec db pg_dump -U nmapuser networkMapper > backup.sql

# Backup uploads and configuration
tar -czf backup-$(date +%Y%m%d).tar.gz uploads/ .env.network ssl/
```

### Updates

```bash
# Pull latest images
docker-compose pull

# Rebuild and restart
docker-compose up -d --build

# Clean old images
docker image prune -f
```

---

## Quick Reference Commands

```bash
# Start development
./scripts/deploy.sh  # Option 1

# Start production with SSL
docker-compose --env-file .env.network -f docker-compose.yml -f docker-compose.ssl.yml up -d

# Generate SSL certificate
openssl genrsa -out ssl/certs/networkmapper.key 2048
openssl req -new -key ssl/certs/networkmapper.key -out ssl/certs/networkmapper.csr
openssl x509 -req -days 365 -in ssl/certs/networkmapper.csr -signkey ssl/certs/networkmapper.key -out ssl/certs/networkmapper.crt

# Create admin user
./scripts/setup-users.sh --prod

# View logs
./scripts/collect-logs.sh

# Health check
curl -k https://localhost/api/v1/health
```

For additional support, refer to the project documentation or submit issues to the project repository.