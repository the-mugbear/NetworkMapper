#!/bin/bash

# NetworkMapper Network Setup Script
# This script configures the application for network access

echo "🌐 Setting up NetworkMapper for network access..."

# Check if .env.network exists
if [ ! -f ".env.network" ]; then
    echo "❌ .env.network file not found!"
    exit 1
fi

# Stop current containers
echo "🛑 Stopping current containers..."
docker-compose down

# Load environment variables and start containers
echo "🚀 Starting containers with network configuration..."
docker-compose --env-file .env.network up -d

# Wait a moment for containers to start
echo "⏳ Waiting for containers to start..."
sleep 10

# Check container status
echo "📊 Container Status:"
docker-compose ps

# Get current IP
CURRENT_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "✅ NetworkMapper is now accessible on the network!"
echo "🖥️  Frontend: http://$CURRENT_IP:3000"
echo "🔧 Backend API: http://$CURRENT_IP:8000"
echo "🗄️  Database: Only accessible internally (secure)"
echo ""
echo "📝 Note: Update .env.network with the correct HOST_IP for production"