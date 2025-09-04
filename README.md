# NetworkMapper 🗺️

A web application that parses Nmap XML scan results and displays them in a human-readable and navigable format.

## Features

- Parse Nmap XML output files
- Store scan results in PostgreSQL database
- Interactive web dashboard with charts and visualizations
- Search and filter scan results
- Export capabilities
- RESTful API for data access

## Tech Stack

- **Backend**: Python with FastAPI
- **Database**: PostgreSQL
- **XML Parsing**: lxml library
- **Frontend**: React with Material-UI
- **Charts**: Chart.js
- **Deployment**: Docker & Docker Compose

## Project Structure

```
NetworkMapper/
├── backend/           # FastAPI backend application
│   ├── app/
│   │   ├── api/      # API routes
│   │   ├── core/     # Core configuration
│   │   ├── db/       # Database models and connection
│   │   ├── parsers/  # Nmap XML parsing logic
│   │   └── schemas/  # Pydantic schemas
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/          # React frontend application
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── utils/
│   ├── package.json
│   └── Dockerfile
├── docker/           # Docker configuration
│   └── docker-compose.yml
└── README.md
```

## Quick Start

1. Clone the repository
2. Run with Docker Compose:
   ```bash
   docker-compose up -d
   ```
3. Access the application at `http://localhost:3000`
4. Upload your Nmap XML files and explore the results!

## Development

### Backend Development
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend Development
```bash
cd frontend
npm install
npm start
```

### Database Setup
The PostgreSQL database will be automatically set up when using Docker Compose.

## API Documentation

Once running, visit `http://localhost:8000/docs` for interactive API documentation.