# THREXA V2
### Think in Graphs. Hunt Smarter.

**An AI-assisted, graph-powered cybersecurity investigation platform.**

THREXA transforms disconnected cybersecurity data into connected, explainable threat intelligence, helping security analysts investigate complex threats, understand infrastructure relationships, and identify potential attack paths.

---

## Overview

Modern cybersecurity environments generate massive amounts of alerts, network events, and asset data. However, understanding how these events connect and how a threat could spread across an organization's infrastructure remains challenging.

Traditional security tools often present isolated alerts and logs, requiring analysts to manually correlate information, investigate relationships, identify potential attack paths, and assess the impact of security incidents.

**THREXA addresses this challenge through graph-powered cybersecurity intelligence.** It connects assets, alerts, network activities, and their relationships into an interactive knowledge graph, enabling analysts to explore threats from a relationship-driven perspective.

The platform combines deterministic graph algorithms with AI-assisted explanations to support transparent, evidence-based security investigations.

## Problem Statement

Security analysts often struggle to correlate disconnected security events, identify hidden relationships between infrastructure components, trace potential attack paths, and assess the possible impact of compromised assets. This fragmented approach makes complex cybersecurity investigations time-consuming and difficult to interpret.

## Our Solution

THREXA converts cybersecurity data into an interactive knowledge graph that connects assets, alerts, network activities, and their relationships. It enables analysts to visualize threat connections, trace potential attack paths, assess potential blast radius, and identify critical choke points. By combining deterministic graph analysis with AI-assisted explanations, THREXA aims to make cybersecurity investigations faster, more understandable, and explainable.

## Key Features

### 1. Interactive Graph Visualization
Explore interconnected assets, alerts, network activities, and relationships through an interactive graph interface.

### 2. Attack Path Finder
Identify potential paths through which a threat could move across connected infrastructure.

### 3. Blast Radius Analysis
Analyze which connected assets could potentially be affected if a particular node is compromised.

### 4. Choke Point Detection
Use graph centrality algorithms to identify structurally important nodes that deserve security attention.

### 5. Threat Correlation
Connect related security events and relationships to help analysts investigate broader threat scenarios.

### 6. AI-Assisted Analyst Copilot
Provide contextual explanations and investigation assistance using AI, while keeping deterministic graph analysis at the core.

### 7. Explainable Investigation
Present graph relationships, supporting evidence, and analysis context to help analysts understand investigation results.

## Target Audience

- Security Operations Center (SOC) Analysts
- Cybersecurity Professionals
- Threat Hunters
- Security Researchers
- IT Infrastructure and Security Teams

## Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React.js, Vite, Tailwind CSS |
| Graph Visualization | Cytoscape.js |
| Backend | Python, FastAPI |
| Graph Database | Neo4j AuraDB |
| Relational Database | PostgreSQL (Neon) |
| Graph Algorithms | NetworkX |
| Data Processing | Pandas, NumPy |
| AI Integration | LLM APIs |
| Authentication | JWT, Argon2id |
| Testing | Pytest |

## System Architecture

```text
                  USERS
                    |
                    v
          REACT + VITE FRONTEND
                    |
              REST API / HTTPS
                    |
                    v
             FASTAPI BACKEND
                    |
       +------------+------------+
       |            |            |
       v            v            v
   AUTHENTICATION  INGESTION   INTELLIGENCE
       |            |            |
       v            v            v
   POSTGRESQL      DATA       NETWORKX
     (NEON)      PROCESSING   GRAPH ENGINE
                    |            |
                    v            v
                 NEO4J AURADB
               GRAPH DATABASE
                    |
                    v
             AI-ASSISTED COPILOT
                    |
                    v
          EXPLAINABLE INVESTIGATIONS
```

## Database Architecture

**PostgreSQL (Neon)**

Responsible for structured application data, including:
- User accounts
- Organizations and memberships
- Roles and permissions
- Authentication sessions
- Email verification records
- Investigation metadata
- Audit logs

**Neo4j AuraDB**

Responsible for graph-based cybersecurity intelligence, including:
- Infrastructure assets
- IP addresses
- Network activities
- Security alerts
- Incidents
- Evidence
- Relationships between entities

## Authentication and Security

THREXA 2.0 is designed with a secure authentication architecture:

- Public user registration
- Email verification
- Secure password hashing using Argon2id
- JWT-based authentication
- Refresh token rotation and revocation
- Role-Based Access Control (RBAC)
- Admin, Analyst, and Viewer roles
- Backend-enforced authorization
- Audit logging

## Project Structure

```text
THREXA/
|
├── backend/
│   ├── app/
│   │   ├── core/
│   │   ├── auth/
│   │   ├── users/
│   │   ├── ingestion/
│   │   ├── graph/
│   │   ├── intelligence/
│   │   ├── copilot/
│   │   ├── investigations/
│   │   ├── audit/
│   │   └── main.py
│   ├── migrations/
│   ├── tests/
│   └── requirements.txt
|
├── frontend/
│   └── src/
│       ├── components/
│       ├── layouts/
│       ├── pages/
│       ├── services/
│       ├── hooks/
│       └── graph/
|
├── datasets/
│   ├── raw/
│   ├── processed/
│   └── samples/
|
├── docs/
├── infrastructure/
├── .env.example
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 20+
- npm
- Git
- Neon PostgreSQL account
- Neo4j AuraDB account

Docker is optional for this setup because PostgreSQL is hosted on Neon.

### 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd THREXA
```

### 2. Backend Setup

```bash
cd backend

python -m venv venv
```

Activate the virtual environment on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file inside the `backend` directory.

```env
APP_NAME=THREXA
APP_ENV=development
DEBUG=true

DATABASE_URL=your_neon_postgresql_connection_string

NEO4J_URI=your_neo4j_uri
NEO4J_USERNAME=your_neo4j_username
NEO4J_PASSWORD=your_neo4j_password

JWT_SECRET_KEY=your_generated_secret
JWT_ALGORITHM=HS256

ACCESS_TOKEN_EXPIRE_MINUTES=10
REFRESH_TOKEN_EXPIRE_DAYS=7

SMTP_HOST=your_smtp_host
SMTP_PORT=587
SMTP_USERNAME=your_smtp_username
SMTP_PASSWORD=your_smtp_password
SMTP_FROM_EMAIL=your_sender_email
```

Never commit `.env` or expose database credentials and secret keys publicly.

### 4. Run the Backend

From the `backend` directory:

```bash
uvicorn app.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

### 5. Frontend Setup

Open another terminal:

```bash
cd frontend

npm install
```

Create a frontend `.env` file:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Start the frontend:

```bash
npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

## Deployment Architecture

The planned cloud deployment architecture:

| Component | Platform |
|---|---|
| Frontend | Vercel |
| Backend | Render |
| PostgreSQL | Neon |
| Graph Database | Neo4j AuraDB |
| AI Services | External LLM API |

Deployment will follow secure environment configuration, HTTPS, database migrations, CORS restrictions, and production email integration.

## Data Sources and Evidence

THREXA is designed to work with public cybersecurity datasets and structured threat knowledge sources.

Initial data-source direction:
- CIC-IDS2017 for network intrusion detection research data.
- MITRE ATT&CK for adversary tactics and techniques knowledge.

Dataset labels must not automatically be treated as confirmed attacker attribution or verified attack techniques. Investigation results should retain source provenance, timestamps, and supporting evidence wherever available.

Public datasets and simulated examples must be clearly distinguished from live enterprise telemetry.

## Development Roadmap

- [x] Initial project foundation
- [x] Technology architecture finalized
- [ ] Authentication and email verification
- [ ] PostgreSQL integration
- [ ] Neo4j AuraDB integration
- [ ] User management and RBAC
- [ ] Cybersecurity data ingestion pipeline
- [ ] Graph construction and normalization
- [ ] Interactive graph explorer
- [ ] Attack Path Finder
- [ ] Blast Radius Analysis
- [ ] Choke Point Detection
- [ ] Threat correlation and temporal analysis
- [ ] Explainable risk analysis
- [ ] AI-assisted analyst copilot
- [ ] Investigation and reporting module
- [ ] Testing and security hardening
- [ ] Cloud deployment

*Roadmap items are planned until implemented and validated.*

## Our Vision

We believe cybersecurity investigations should go beyond isolated alerts and disconnected logs.

With THREXA, our goal is to make complex threat relationships easier to explore, understand, and investigate through graph-powered intelligence.

**THINK. BUILD. SECURE. REPEAT.**

---

**Project:** THREXA 2.0  
**Tagline:** Think in Graphs. Hunt Smarter.  
**Team:** 404Vision / QUBRIX (depending on the event or repository ownership)  
**Domain:** Cybersecurity | Graph Intelligence | AI-Assisted Threat Investigation

*Built with curiosity, collaboration, and a vision to make cybersecurity investigations smarter.*

