# Development Guide

## Quick Development Setup (No Rebuilds)

### Option 1: Use Development Docker Compose
Use the development compose file with volume mounts for hot reloading:

```bash
docker-compose -f docker-compose.dev.yml up
```

This mounts your source code as volumes, so changes are reflected immediately without rebuilds.

### Option 2: Run Components Separately

#### 1. Start PostgreSQL only
```bash
docker run -d --name networkmap-postgres \
  -e POSTGRES_DB=networkMapper \
  -e POSTGRES_USER=nmapuser \
  -e POSTGRES_PASSWORD=nmappass \
  -p 5432:5432 \
  postgres:15
```

#### 2. Run Backend (Python FastAPI)
```bash
cd backend
pip install -r requirements.txt
export DATABASE_URL="postgresql://nmapuser:nmappass@localhost:5432/networkMapper"
export CORS_ORIGINS="http://localhost:3000"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### 3. Run Frontend (React)
```bash
cd frontend
npm install
export REACT_APP_API_URL="http://localhost:8000"
npm start
```

### Option 3: Hybrid Approach
Run PostgreSQL in Docker, but backend/frontend locally:

```bash
# Start just the database
docker-compose up db

# Run backend locally
cd backend
pip install -r requirements.txt
export DATABASE_URL="postgresql://nmapuser:nmappass@localhost:5433/networkMapper"  # Note: port 5433 if using docker-compose
uvicorn app.main:app --reload

# Run frontend locally (in another terminal)
cd frontend
npm install
npm start
```

## Installing New Dependencies

### Backend Dependencies
When you add new Python packages:

```bash
# Add to requirements.txt, then:
cd backend
pip install -r requirements.txt

# Or install directly:
pip install package_name
pip freeze > requirements.txt
```

### Frontend Dependencies
When you add new npm packages:

```bash
cd frontend
npm install package_name
# Package.json is automatically updated
```

## Database Changes
The application uses SQLAlchemy with automatic table creation. When you modify models in `app/db/models.py`, tables are automatically created/updated on startup.

For production, you might want to use proper migrations with Alembic:

```bash
cd backend
alembic init alembic
alembic revision --autogenerate -m "Add new models"
alembic upgrade head
```

## Hot Reloading

### Backend (FastAPI)
- Use `--reload` flag with uvicorn for automatic reloading on code changes
- Works with both local and Docker development setups

### Frontend (React)
- React's development server automatically reloads on changes
- Set `CHOKIDAR_USEPOLLING=true` in Docker for better file watching

## Testing New Features

1. **DNS Features**: Ensure you have internet connectivity for DNS lookups
2. **File Uploads**: Test with sample files:
   - Nmap: `nmap -sS -O 127.0.0.1 -oX sample.xml`
   - Masscan: `masscan -p80,443 127.0.0.1 -oX sample.xml`
3. **Export Features**: Test all three formats (JSON, CSV, HTML)

## Performance Tips

- **Database**: Use PostgreSQL instead of SQLite for better performance
- **DNS Lookups**: Be cautious with DNS enrichment on large scans
- **File Uploads**: Large Masscan outputs can take time to process

## Troubleshooting

### Port Conflicts
If ports 3000, 8000, or 5432 are in use:
- Change ports in docker-compose files
- Update environment variables accordingly

### Database Connection Issues
- Ensure PostgreSQL is running
- Check DATABASE_URL format
- Verify firewall settings

### Frontend Build Issues
- Clear npm cache: `npm cache clean --force`
- Delete node_modules and reinstall: `rm -rf node_modules && npm install`

### Backend Import Issues
- Ensure all dependencies are installed
- Check Python path and virtual environment
- Verify database models are properly imported