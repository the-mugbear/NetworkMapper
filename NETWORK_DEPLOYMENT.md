# NetworkMapper Dynamic Network Deployment

This guide explains how to deploy NetworkMapper with automatic network configuration for production environments.

## 🚀 Quick Start (Fully Automatic)

For production deployment with zero manual configuration:

```bash
# Clone and enter the project
git clone <repository-url>
cd NetworkMapper

# Deploy with automatic network detection
./setup-network.sh --auto
```

That's it! The system will:
- Automatically detect your network IP address
- Generate the correct environment configuration
- Start all services with network access
- Display the access URLs

## 📋 Available Deployment Methods

### Method 1: Fully Automatic (Recommended)
```bash
./setup-network.sh --auto
```
- Detects network IP automatically
- Generates `.env.network` configuration
- Starts services immediately

### Method 2: Pre-generate Configuration
```bash
# Generate network configuration first
bash scripts/detect-network-config.sh

# Review and optionally edit .env.network
cat .env.network

# Deploy with existing configuration
./setup-network.sh
```

### Method 3: Manual Configuration (Legacy)
```bash
# Create .env.network manually
cp .env.network.example .env.network
# Edit HOST_IP, REACT_APP_API_URL, CORS_ORIGINS

# Deploy
./setup-network.sh
```

## 🔧 Dynamic Network Detection Features

The automatic detection system includes:

### **Multiple Detection Methods**
1. **Default Route Method**: Uses `ip route get 8.8.8.8` (most reliable)
2. **Primary Interface Method**: Gets IP from default route interface
3. **Hostname Method**: Uses `hostname -I` command
4. **Interface Scanning**: Scans all non-loopback interfaces

### **Environment Support**
- ✅ **Physical Servers**: Direct network interface detection
- ✅ **Virtual Machines**: Works with virtualized networking
- ✅ **Docker Environments**: Special handling for containerized deployments
- ✅ **Cloud Instances**: AWS EC2, Google Cloud, Azure VMs
- ✅ **Multi-NIC Systems**: Selects best primary interface

### **Fallback Mechanisms**
- Multiple detection algorithms try in sequence
- Validates IP addresses before using
- Tests network connectivity when possible
- Provides detailed error messages for troubleshooting

## 🌐 Generated Configuration

The system automatically creates `.env.network` with:

```bash
# Network configuration for external access
# Auto-generated on [timestamp]
HOST_IP=192.168.1.100

# Frontend will connect to this backend URL
REACT_APP_API_URL=http://192.168.1.100:8000

# Backend will allow CORS from these origins
CORS_ORIGINS=http://localhost:3000,http://192.168.1.100:3000
```

## 🛠️ Advanced Usage

### Force Regeneration
```bash
# Regenerate network config even if it exists
./setup-network.sh --auto

# Or manually regenerate
bash scripts/detect-network-config.sh
```

### Debug Network Detection
```bash
# View detailed network information
bash scripts/detect-network-config.sh

# Check current network interfaces
ip -4 addr show
ip route
```

### Custom IP Override
```bash
# Set specific IP (bypasses detection)
export HOST_IP="10.0.0.50"
./setup-network.sh --auto
```

## 🔍 Troubleshooting

### Common Issues

**"Could not detect a valid IP address"**
- Check if network interfaces are up: `ip link show`
- Verify routing table: `ip route`
- Try manual detection: `hostname -I`

**"Application not accessible from network"**
- Verify firewall settings (ports 3000, 8000)
- Check if IP is correct: `ping <detected-ip>`
- Ensure services are bound to all interfaces (0.0.0.0)

**"CORS errors in browser"**
- Confirm CORS_ORIGINS includes your IP
- Check browser network tab for actual request origins
- Verify backend is using environment variables

### Manual Verification

```bash
# Check generated configuration
cat .env.network

# Verify services are running
docker-compose ps

# Test API connectivity
curl http://<your-ip>:8000/health

# Check backend CORS configuration
curl -H "Origin: http://<your-ip>:3000" http://<your-ip>:8000/api/v1/dashboard/stats
```

## 🏗️ Production Deployment Notes

### Security Considerations
- Database is only accessible internally (not exposed to network)
- Frontend and backend are exposed on all interfaces (0.0.0.0)
- CORS is configured for specific origins only
- Consider adding reverse proxy (nginx) for production

### Performance Optimization
- Use `docker-compose.prod.yml` for production optimizations
- Configure proper logging levels
- Set up health monitoring
- Consider using Docker Swarm or Kubernetes for scaling

### Firewall Configuration
Ensure these ports are accessible:
- **3000**: Frontend (React application)
- **8000**: Backend API (FastAPI)
- **5432**: Database (internal only, blocked from external)

## 📚 Files Overview

- **`setup-network.sh`**: Main deployment script with auto-detection
- **`scripts/detect-network-config.sh`**: Network detection utility
- **`.env.network`**: Generated network configuration
- **`docker-compose.yml`**: Container orchestration
- **`NETWORK_DEPLOYMENT.md`**: This documentation

## 🆘 Support

For issues with network deployment:
1. Check this documentation first
2. Run diagnostics: `bash scripts/detect-network-config.sh`
3. Review container logs: `docker-compose logs`
4. Check GitHub issues for similar problems

---

**Example Successful Deployment:**
```
🌐 Setting up NetworkMapper for network access...
🌐 Generating dynamic network configuration...
ℹ️  NetworkMapper Dynamic Network Configuration Detection
ℹ️  ==================================================
ℹ️  Detecting network interfaces...
ℹ️  Using IP from default route: 192.168.1.100
✅ Detected IP address: 192.168.1.100
✅ IP 192.168.1.100 is assigned to a network interface
ℹ️  Generating network configuration: .env.network
✅ Generated network configuration:
ℹ️  HOST_IP=192.168.1.100
ℹ️  REACT_APP_API_URL=http://192.168.1.100:8000
ℹ️  CORS_ORIGINS=http://localhost:3000,http://192.168.1.100:3000
🌐 Stopping current containers...
🌐 Starting containers with network configuration...
🌐 Waiting for containers to start...
✅ NetworkMapper is now accessible on the network!
🖥️  Frontend: http://192.168.1.100:3000
🔧 Backend API: http://192.168.1.100:8000
🗄️  Database: Only accessible internally (secure)
```