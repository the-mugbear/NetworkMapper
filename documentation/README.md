# NetworkMapper 🗺️

A comprehensive network security assessment platform that parses multiple scan formats, performs risk analysis, and provides detailed security insights through an interactive dashboard.

## Features

- **Multi-format Parsing**: Nmap XML, Masscan, Eyewitness, DNS records
- **Risk Assessment**: Comprehensive security analysis with vulnerability detection
- **Interactive Dashboard**: Real-time charts, visualizations, and risk summaries
- **User Authentication**: Role-based access control (admin, analyst, viewer)
- **Search and Filtering**: Advanced search across hosts, ports, and vulnerabilities
- **Export Capabilities**: Multiple export formats with custom templates
- **RESTful API**: Complete API access for automation and integration

## Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy
- **Database**: PostgreSQL with risk assessment tables
- **Frontend**: React 18, TypeScript, Material-UI v5, Chart.js
- **Authentication**: JWT tokens with role-based permissions
- **Deployment**: Docker, Docker Compose with multi-stage builds

## Project Structure

```
NetworkMapper/
├── backend/                 # FastAPI backend application
│   ├── app/
│   │   ├── api/v1/         # API routes and endpoints
│   │   │   └── endpoints/  # Individual endpoint modules
│   │   ├── core/           # Core configuration and security
│   │   ├── db/             # Database models and sessions
│   │   │   ├── models.py   # Core host/port models
│   │   │   ├── models_auth.py    # Authentication models
│   │   │   └── models_risk.py    # Risk assessment models
│   │   ├── parsers/        # Multi-format parsing logic
│   │   ├── schemas/        # Pydantic response schemas
│   │   └── services/       # Business logic services
│   │       ├── risk_assessment_service.py
│   │       └── vulnerability_db_service.py
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/               # React TypeScript frontend
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   │   ├── HostRiskAnalysis.tsx
│   │   │   ├── CriticalFindingsWidget.tsx
│   │   │   └── RiskSummaryWidget.tsx
│   │   ├── contexts/       # React contexts (auth, etc.)
│   │   ├── pages/          # Route-level page components
│   │   └── services/       # API communication layer
│   ├── package.json
│   └── Dockerfile
├── documentation/          # Project documentation
│   ├── ARCHITECTURE.md     # System architecture overview
│   ├── CVE_INTEGRATION_PLAN.md  # Vulnerability database plans
│   ├── NETWORK_DEPLOYMENT.md   # Production deployment guide
│   └── TESTING_FRAMEWORK_DOCUMENTATION.md
├── artifacts/              # Sample scan files and test data
├── docker-compose.yml      # Complete stack orchestration
├── CLAUDE.md              # Development guidelines for Claude Code
└── README.md              # This file (symlink to documentation/README.md)
```

## Quick Start

### Production Deployment
```bash
# Unified deployment script with all options
./scripts/deploy.sh

# Check status of all instances
./scripts/status.sh

# Collect comprehensive logs
./scripts/collect-logs.sh
```

### Development
```bash
# Start full stack
docker-compose up -d

# Access application
open http://localhost:3000

# Create initial users
./scripts/setup-users.sh --all
```

## Development Setup

### Backend Development
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development
```bash
cd frontend
npm install
npm start                    # Development server with hot reload
npm run build               # Production build
npm test                    # Run tests
```

### Database Setup
PostgreSQL database with risk assessment schema is automatically configured via Docker Compose.

## Key Features

### Risk Assessment System
- **Vulnerability Analysis**: Pattern-based detection with local CVE database
- **Configuration Assessment**: Security misconfigurations and weak settings
- **Attack Surface Analysis**: Exposed services and dangerous ports
- **Risk Scoring**: CVSS-based scoring with weighted algorithms
- **Remediation Guidance**: Actionable security recommendations

### Authentication & Authorization
- **JWT-based Authentication**: Secure token-based sessions
- **Role-based Access**: Admin, analyst, viewer, auditor roles
- **Protected Routes**: Frontend route protection
- **API Security**: Bearer token authentication on all endpoints

### Data Sources
- **Network Scans**: Nmap XML, Masscan JSON/XML/list
- **Web Screenshots**: Eyewitness JSON/CSV
- **DNS Data**: Forward/reverse lookups, zone transfers
- **Vulnerability Patterns**: Local database with common CVEs

## API Documentation

- **Interactive Docs**: http://localhost:8000/docs
- **OpenAPI Schema**: http://localhost:8000/openapi.json
- **Health Check**: http://localhost:8000/health

## Monitoring & Debugging

```bash
# Check status of all instances
./scripts/status.sh

# Collect comprehensive logs
./scripts/collect-logs.sh

# Deploy test instance alongside production
./scripts/deploy.sh  # Select option 3 for test instance

# Monitor risk assessments
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/risk/hosts/risk-summary
```

## Security Considerations

- **No External API Calls**: All vulnerability analysis is performed locally
- **Data Privacy**: Host information never leaves your network
- **Authentication Required**: All risk assessment endpoints protected
- **Input Validation**: Comprehensive file format validation
- **SQL Injection Protection**: Parameterized queries via SQLAlchemy

## Documentation

- **[Architecture](ARCHITECTURE.md)**: System design and components
- **[CVE Integration Plan](CVE_INTEGRATION_PLAN.md)**: Vulnerability database roadmap
- **[Network Deployment](NETWORK_DEPLOYMENT.md)**: Production deployment guide
- **[Testing Framework](TESTING_FRAMEWORK_DOCUMENTATION.md)**: Testing approach and tools

## Version Information

- **Backend**: v1.2.1
- **Frontend**: v1.4.1
- **Database Schema**: v2 with deduplication support
- **Risk Assessment**: Pattern-based with local CVE database

## Contributing

Refer to `CLAUDE.md` for development guidelines and build instructions.