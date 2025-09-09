# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Production Deployment
```bash
# Standard deployment with network configuration
./setup-network.sh

# Nuclear option for persistent Docker cache issues
./force-clean-rebuild.sh

# Local development
docker-compose up -d

# Development with hot reload
docker-compose -f docker-compose.dev.yml up
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
# Collect comprehensive logs for debugging
./collect-logs.sh

# Check container status
docker-compose ps
docker-compose logs [service]

# API documentation
curl http://localhost:8000/docs  # Interactive API docs
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
- **Version Verification**: Scripts automatically verify backend (1.1.0) and frontend (1.3.0) versions
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