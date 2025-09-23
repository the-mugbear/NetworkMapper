# NetworkMapper Scripts

This directory contains utility scripts for deployment, maintenance, and user management.

## Scripts Overview

### Deployment Scripts

- **`deploy.sh`** - **Main deployment script** with all deployment options
  - Local development deployment
  - Network production deployment
  - Test instance deployment
  - Nuclear clean rebuild
  - Ultra-fresh network deployment

### Maintenance Scripts

- **`collect-logs.sh`** - Comprehensive log collection with authentication debugging
- **`status.sh`** - Quick status check for all instances

### User Management Scripts

- **`setup-users.sh`** - User setup wrapper script (recommended)
- **`create_admin_user.py`** - Direct Python script for user creation

## Quick Start - User Setup

### Create Initial Admin User (Interactive)
```bash
./scripts/setup-users.sh
```

### Create Admin + Test Users
```bash
./scripts/setup-users.sh --all
```

### Create Only Test Users
```bash
./scripts/setup-users.sh --samples-only
```

## User Setup Options

### Interactive Admin Creation
The setup script will guide you through creating an admin user with:
- Username validation (unique)
- Email validation (unique, format check)
- Password strength validation
- Optional full name

### Sample Test Users
When creating sample users, you get:
- **analyst1** / AnalystPassword123! (ANALYST role)
- **viewer1** / ViewerPassword123! (VIEWER role)
- **auditor1** / AuditorPassword123! (AUDITOR role)

## User Roles

- **ADMIN**: Full system access, user management, configuration
- **ANALYST**: Risk assessments, detailed analysis, report generation
- **VIEWER**: Read-only access to scan results and dashboards
- **AUDITOR**: Read access + export capabilities for compliance

## Password Requirements

Passwords must meet these criteria:
- At least 8 characters long
- Contains uppercase letters
- Contains lowercase letters
- Contains numbers
- Contains special characters
- Not commonly used weak passwords

## Advanced Usage

### Direct Python Script
```bash
# From backend directory
cd backend
python ../scripts/create_admin_user.py

# Create sample users only
python ../scripts/create_admin_user.py --samples
```

### Docker Container Execution
```bash
# Create admin user inside running container
docker-compose exec backend python /app/scripts/create_admin_user.py

# Create sample users
docker-compose exec backend python /app/scripts/create_admin_user.py --samples
```

## Troubleshooting

### Backend Not Running
If you get connection errors:
```bash
# Start the backend services
docker-compose up -d backend db

# Wait for services to be ready, then retry
./scripts/setup-users.sh
```

### Database Connection Issues
If database connection fails:
```bash
# Check container status
docker-compose ps

# Check logs
docker-compose logs backend
docker-compose logs db

# Force restart
docker-compose restart backend db
```

### Permission Errors
If you get permission errors:
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Or run with bash
bash scripts/setup-users.sh
```

## Script Dependencies

All scripts require:
- Docker and Docker Compose
- Running NetworkMapper backend container
- PostgreSQL database connectivity

The setup-users.sh script will automatically:
- Check if backend is running
- Start services if needed
- Wait for backend readiness
- Execute user creation scripts

## Integration with Deployment

The user setup script is designed to work with deployment scripts:

```bash
# Full deployment with user setup
./scripts/deploy.sh      # Select option 2 for network production
./scripts/setup-users.sh --all

# The deploy.sh script can prompt for user creation automatically
```