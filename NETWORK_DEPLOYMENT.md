# NetworkMapper Network Deployment

This guide explains how to deploy NetworkMapper for network access in production environments.

## 🚀 Quick Start

For production deployment:

```bash
# Clone and enter the project
git clone <repository-url>
cd NetworkMapper

# Create network configuration
cp .env.network.example .env.network

# Edit .env.network with your server's IP address
# Replace YOUR_SERVER_IP with your actual IP

# Deploy
./setup-network.sh
```

## 📋 Deployment Configuration

### Step 1: Configure Network Settings
```bash
# Copy the example configuration
cp .env.network.example .env.network

# Edit the configuration file
nano .env.network
```

Update these values in `.env.network`:
- `HOST_IP`: Your server's IP address
- `REACT_APP_API_URL`: Backend API URL (http://YOUR_IP:8000)
- `CORS_ORIGINS`: Allowed frontend origins

### Step 2: Deploy Application
```bash
# Start services with network configuration
./setup-network.sh
```

## 🌐 Configuration Format

The `.env.network` file should contain:

```bash
# Network configuration for external access
HOST_IP=192.168.1.100

# Frontend will connect to this backend URL
REACT_APP_API_URL=http://192.168.1.100:8000

# Backend will allow CORS from these origins
CORS_ORIGINS=http://localhost:3000,http://192.168.1.100:3000
```

### Configuration Examples

**Local Network Deployment:**
```bash
HOST_IP=192.168.1.100
REACT_APP_API_URL=http://192.168.1.100:8000
CORS_ORIGINS=http://localhost:3000,http://192.168.1.100:3000
```

**Cloud Server Deployment:**
```bash
HOST_IP=10.0.1.50
REACT_APP_API_URL=http://10.0.1.50:8000
CORS_ORIGINS=http://localhost:3000,http://10.0.1.50:3000
```

**Public Server Deployment:**
```bash
HOST_IP=203.0.113.10
REACT_APP_API_URL=http://203.0.113.10:8000
CORS_ORIGINS=http://localhost:3000,http://203.0.113.10:3000
```

## 🛠️ Advanced Usage

### Finding Your Server IP

**For Local Networks:**
```bash
# Check your local IP address
ip addr show | grep 'inet ' | grep -v 127.0.0.1
# or
hostname -I
```

**For Cloud Instances:**
- AWS EC2: Use private IP from instance metadata
- Google Cloud: Use internal IP from VM instance details
- Azure: Use private IP from VM network settings

### Updating Configuration
```bash
# Edit existing configuration
nano .env.network

# Restart services with new config
./setup-network.sh
```

## 🔍 Troubleshooting

### Common Issues

**".env.network file not found"**
- Copy the example file: `cp .env.network.example .env.network`
- Edit with your server's IP address

**"Application not accessible from network"**
- Verify firewall settings (ports 3000, 8000)
- Check if IP is correct: `ping <your-ip>`
- Ensure services are bound to all interfaces (0.0.0.0)

**"CORS errors in browser"**
- Confirm CORS_ORIGINS includes your IP in .env.network
- Check browser network tab for actual request origins
- Verify backend is using environment variables

### Manual Verification

```bash
# Check configuration
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

- **`setup-network.sh`**: Main deployment script
- **`.env.network.example`**: Network configuration template
- **`.env.network`**: Your network configuration (create from example)
- **`docker-compose.yml`**: Container orchestration
- **`NETWORK_DEPLOYMENT.md`**: This documentation

## 🆘 Support

For issues with network deployment:
1. Check this documentation first
2. Verify your .env.network configuration
3. Review container logs: `docker-compose logs`
4. Check GitHub issues for similar problems

---

## 🎯 Summary: Changes Required for New Host Deployment

When deploying on a new host, you need to:

1. **Copy configuration template:**
   ```bash
   cp .env.network.example .env.network
   ```

2. **Update IP addresses in .env.network:**
   - Change `HOST_IP` to your server's IP
   - Update `REACT_APP_API_URL` to use your server's IP
   - Update `CORS_ORIGINS` to include your server's IP

3. **Deploy:**
   ```bash
   ./setup-network.sh
   ```

4. **Verify firewall settings:**
   - Ensure ports 3000 and 8000 are accessible
   - Database port 5432 should remain internal only

**Example: Moving from 192.168.7.236 to 10.0.1.50:**
```bash
# Old configuration
HOST_IP=192.168.7.236
REACT_APP_API_URL=http://192.168.7.236:8000
CORS_ORIGINS=http://localhost:3000,http://192.168.7.236:3000

# New configuration
HOST_IP=10.0.1.50
REACT_APP_API_URL=http://10.0.1.50:8000
CORS_ORIGINS=http://localhost:3000,http://10.0.1.50:3000
```