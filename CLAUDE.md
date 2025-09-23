# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Production Deployment
```bash
# Unified deployment script (recommended)
./scripts/deploy.sh

# Direct deployment options:
# Local development (HTTP)
docker-compose --env-file .env.development up -d

# Production (HTTPS with SSL)
SSL_MODE=true HTTPS_PORT=443 docker-compose --env-file .env.network up -d

# Test instance (alternate ports)
docker-compose --env-file .env.test up -d
```

### Frontend Commands
```bash
cd frontend
npm install
npm start                    # Development server with hot reload
npm run build               # Production build
npm test                    # Run tests
node generate-build-info.js # Generate build info (runs automatically)
```

### Backend Commands
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000  # Development server
```

### Troubleshooting and Debugging
```bash
# Collect comprehensive logs for debugging (includes auth/audit logs)
./scripts/collect-logs.sh

# Check container status
docker-compose ps
docker-compose logs [service]

# API documentation
curl http://localhost:8000/docs  # Interactive API docs

# Authentication debugging (browser console)
localStorage.getItem('auth_token')    # Check JWT token
localStorage.getItem('auth_user')     # Check user data
logger.getAuthLogs()                  # Get auth logs (if available)
```

## Architecture Overview

NetworkMapper is a web application for parsing and visualizing network scan results with a modern FastAPI backend and React frontend.

### Core Architecture
- **Backend**: FastAPI application with PostgreSQL database
- **Frontend**: React with Material-UI and TypeScript
- **Parsers**: Modular parser system for different scan formats
- **Services**: Business logic layer for data processing and enrichment
- **API**: RESTful API with comprehensive endpoint coverage

### Parser System
The application uses a modular parser architecture in `backend/app/parsers/`:
- `nmap_parser.py` - XML format parsing with host correlation
- `gnmap_parser.py` - Grepable format parsing (lazy imported to prevent module loading issues)
- `masscan_parser.py` - Masscan XML/JSON/list format support
- `eyewitness_parser.py` - Web screenshot tool integration
- `dns_parser.py` - DNS records and PTR parsing
- `subnet_parser.py` - Network scope management

### Database Models
Core entities in `backend/app/db/models.py`:
- **Scan** - Container for scan metadata and results
- **Host** - Network hosts with OS detection and state information
- **Port** - Service information with script output
- **Scope/Subnet** - Network boundary management with automatic correlation
- **DNSRecord** - DNS enrichment data
- **ParseError** - Error tracking and debugging support

### API Structure
Endpoints organized by functionality in `backend/app/api/v1/endpoints/`:
- `/upload` - File upload with multi-format support and lazy parser loading
- `/scans` - Scan management and listing with summary statistics
- `/hosts` - Host details and filtering with subnet correlation
- `/dashboard` - Analytics and summary statistics
- `/scopes` - Network scope management with subnet upload
- `/export` - Data export in multiple formats
- `/dns` - DNS enrichment and lookup services
- `/parse-errors` - Error tracking and troubleshooting

### Frontend Architecture
React application in `frontend/src/` with:
- **Pages**: Route-level components for major functionality
- **Components**: Reusable UI components including VersionFooter
- **Services**: API communication layer with axios
- **Build System**: Custom build info generation that reads from package.json

### Configuration and Environment
- **Network Deployment**: Uses `.env.network` for production network configuration
- **CORS Configuration**: Dynamic CORS origins based on deployment environment  
- **Version Management**: Frontend version read from package.json, backend version in main.py
- **Docker Cache Busting**: ARG CACHE_BUST in Dockerfiles with timestamp-based invalidation

### Key Services
- **SubnetCorrelationService**: Automatically maps hosts to network scopes
- **DNSService**: Enriches host data with reverse DNS and zone transfer attempts
- **ExportService**: Handles data export with templating support
- **ParseErrorService**: Tracks parsing failures for debugging and user feedback

### Deployment Considerations
- **Docker Caching**: Use enhanced setup scripts to prevent stale code deployment
- **Version Verification**: Scripts automatically verify backend (1.2.1) and frontend (1.4.1) versions
- **CORS Issues**: Network deployments require proper IP configuration in .env.network
- **Build Info**: Frontend version footer requires generate-build-info.js to run during build

### File Upload Support
Supported formats with lazy loading for problematic parsers:
- `.xml` - Nmap XML, Masscan XML
- `.gnmap` - Nmap grepable format (lazy imported)
- `.json` - Masscan JSON, Eyewitness JSON  
- `.csv` - Eyewitness CSV, DNS records
- `.txt` - Masscan list format

### Testing and Validation
- **Health Checks**: `/health` endpoint for deployment verification
- **Version Endpoints**: API root endpoint returns current version
- **Log Aggregation**: Comprehensive logging with collect-logs.sh script
- **Error Tracking**: ParseError system with user-friendly error IDs

## Architecture v2 - Host Deduplication

NetworkMapper v2 introduces host deduplication at the database level to eliminate duplicate entries when the same IP appears in multiple scans.

### Key Improvements
- **Single Host per IP**: Hosts are unique by IP address across all scans
- **Port Aggregation**: All ports from all scans combined per host
- **Audit Tracking**: Complete scan history preserved in audit tables
- **Conflict Resolution**: Intelligent merging of scan data with configurable strategies

### V2 Components
- **models_v2.py**: New deduplicated schema with audit tables
- **HostDeduplicationService**: Core deduplication and conflict resolution logic
- **nmap_parser_v2.py**: Parser using deduplication service
- **hosts_v2.py**: Simplified API endpoints for deduplicated data
- **feature_flags.py**: Gradual rollout system for v2 features

### Migration Strategy
- **Phase 1**: Deploy v2 code (flags disabled)
- **Phase 2**: Run migration to create v2 tables
- **Phase 3**: Enable dual-write mode for validation
- **Phase 4**: Switch to v2 completely
- **Phase 5**: Optional cleanup of v1 tables

### Feature Flags
```bash
USE_V2_SCHEMA=true          # Enable v2 database tables
USE_V2_PARSER=true          # Use deduplication parser
USE_V2_HOSTS_API=true       # Use v2 hosts endpoint
DUAL_WRITE_MODE=true        # Parse with both v1/v2 for validation
MIGRATION_MODE=true         # Special migration behaviors
```

### Benefits
- **60-80% reduction** in duplicate host/port records
- **Simpler queries** - no aggregation needed in API
- **Better data quality** with intelligent conflict resolution
- **Complete audit trail** for compliance and debugging
- **Improved performance** with better indexing and smaller dataset

### Migration Commands
```bash
# Create v2 tables and migrate data
docker-compose exec backend python -m app.db.migrate_to_v2 migrate

# Verify migration integrity
docker-compose exec backend python -m app.db.migrate_to_v2 verify

# Test deduplication logic
docker-compose exec backend python simple_dedup_test.py

# Rollback if needed
docker-compose exec backend python -m app.db.migrate_to_v2 rollback
```

### Monitoring v2
- Check for duplicate IPs: `SELECT ip_address, COUNT(*) FROM hosts_v2 GROUP BY ip_address HAVING COUNT(*) > 1`
- Deduplication stats: Query `host_scan_history` for multi-scan hosts
- Performance: Compare query times between v1 and v2 endpoints

See `V2_ARCHITECTURE.md` for complete technical details.

## Unified Deployment System

NetworkMapper now uses a consolidated deployment script that replaces multiple individual scripts:

### New Unified Script
```bash
./scripts/deploy.sh
```

**Deployment Options:**
1. **Local Development** - Quick localhost setup for development
2. **Network Production** - Production deployment using .env.network
3. **Test Instance** - Parallel test deployment (ports 3001/8001)
4. **Nuclear Clean** - Remove all Docker data and rebuild
5. **Ultra-Fresh Network** - Aggressive cache-busting network deployment

### Available Scripts
- `./scripts/deploy.sh` - **Main deployment script** with all deployment options
- `./scripts/collect-logs.sh` - Comprehensive log collection with auth debugging
- `./scripts/setup-users.sh` - User account management
- `./scripts/status.sh` - Quick status check

### Authentication & Logging

The application includes comprehensive authentication logging:
- **Frontend**: Browser-based logging with audit trails
- **Backend**: JWT authentication with audit endpoints
- **Log Collection**: Enhanced `./scripts/collect-logs.sh` captures auth logs

**Debug Authentication Issues:**
```javascript
// Browser console commands
localStorage.getItem('auth_token')       // Check JWT token
localStorage.getItem('auth_user')        // Check user object
logger.getAuthLogs()                     // Get authentication logs
logger.exportLogs()                      // Export all logs
```

**Working Test Credentials:**
```
Username: testadmin2
Password: admin123
Role: admin
```