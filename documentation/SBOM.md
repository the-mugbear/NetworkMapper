# Software Bill of Materials (SBOM)

This document provides a list of software components used in the NetworkMapper application.

## Backend (Python)

Dependencies are managed in `backend/requirements.txt`.

| Package | Version | License |
|---|---|---|
| fastapi | 0.117.1 | MIT |
| uvicorn | 0.36.0 | BSD-3-Clause |
| sqlalchemy | 2.0.43 | MIT |
| psycopg2-binary | 2.9.10 | LGPL with exceptions |
| alembic | 1.16.5 | MIT |
| pydantic | 2.11.9 | MIT |
| python-multipart | 0.0.20 | Apache-2.0 |
| lxml | 6.0.1 | BSD-3-Clause |
| python-dateutil | 2.9.0.post0 | Dual License: Apache-2.0 / BSD-3-Clause |
| typing-extensions | 4.15.0 | Python Software Foundation License |
| dnspython | 2.8.0 | ISC |
| ipaddress | 1.0.23 | Python Software Foundation License |
| pytest | 8.4.2 | MIT |
| pytest-cov | 7.0.0 | MIT |
| pytest-asyncio | 1.2.0 | Apache-2.0 |
| httpx | 0.28.1 | BSD-3-Clause |
| click | 8.3.0 | BSD-3-Clause |
| starlette | 0.48.0 | BSD-3-Clause |
| typer | 0.19.1 | MIT |
| passlib | 1.7.4 | BSD-3-Clause |
| bcrypt | 3.2.2 | Apache-2.0 |
| PyJWT | 2.8.0 | MIT |
| python-jose | 3.3.0 | MIT |

## Frontend (JavaScript/TypeScript)

Dependencies are managed in `frontend/package.json` and `frontend/package-lock.json`.

| Package | Version | License |
|---|---|---|
| @emotion/react | 11.13.3 | MIT |
| @emotion/styled | 11.13.0 | MIT |
| @mui/icons-material | 6.3.0 | MIT |
| @mui/material | 6.3.0 | MIT |
| @mui/x-data-grid | 7.22.2 | MIT |
| axios | 1.7.7 | MIT |
| chart.js | 4.4.6 | MIT |
| react | 18.3.1 | MIT |
| react-chartjs-2 | 5.2.0 | MIT |
| react-dom | 18.3.1 | MIT |
| react-dropzone | 14.3.5 | MIT |
| react-router-dom | 6.28.0 | MIT |
