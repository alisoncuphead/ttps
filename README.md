# CTI Analysis & Attribution Engine (TTP-AE)

An AI-powered Cyber Threat Intelligence (CTI) platform that transforms raw security reports (HTML/PDF) into a structured **Knowledge Graph**. It automates the extraction of actors, victims, IoCs, and TTPs, grounding them against the **MITRE ATT&CK** framework to enable behavioral attribution and campaign clustering.

## 🚀 Key Features
- **Multimodal Extraction:** High-performance text extraction from web URLs and PDF whitepapers.
- **LLM-Driven Analysis:** Uses `deepseek-r1` via Ollama for sophisticated reasoning and structured JSON extraction.
- **Semantic Grounding:** Two-stage TTP mapping using Qdrant vector search followed by LLM-based verification.
- **Knowledge Graph Ingestion:** Automatically builds relationships in Neo4j (`Actor -[USES]-> TTP`, `Actor -[TARGETS]-> Victim`).
- **Behavioral Clustering:** Identifies clusters of threat actors based on shared TTP overlaps.
- **Analyst Dashboard:** A clean, dark-themed UI for report submission and graph exploration.

## 🏗 Project Structure
```text
ttps/
├── app/
│   ├── main.py              # FastAPI entry point & route mounting (Dashboard, Analyze, Graph)
│   ├── api/                 # API route definitions
│   ├── core/                # System configuration & environment settings
│   ├── models/
│   │   └── extraction.py    # Pydantic schemas for validated CTI data
│   ├── services/
│   │   ├── crawler.py       # HTML (BS4) and PDF (PyMuPDF) acquisition logic
│   │   ├── extractor.py     # Ollama/DeepSeek-R1 orchestration & validation
│   │   ├── grounding.py     # Qdrant semantic search & entity normalization
│   │   └── graph_store.py   # Neo4j ingestion & attribution queries
│   └── static/
│       └── index.html       # Vanilla JS/CSS Analyst Dashboard
├── seed_database.py         # Utility to index MITRE ATT&CK STIX data into Qdrant
├── compose.yml              # Multi-container setup (API, Qdrant, Ollama, Neo4j)
├── requirements.txt         # Python dependencies
└── GEMINI.md                # Project roadmap and internal dev mandates
```

## 🛠 Getting Started

### 1. Prerequisites
- Docker & Docker Compose
- Python 3.11+
- [Ollama](https://ollama.ai/) (Running locally or as a container)

### 2. Infrastructure Setup
```bash
# Start Qdrant, Neo4j, and the API
docker-compose up -d

# Pull the required LLM (if not using the containerized Ollama)
ollama pull deepseek-r1:8b
```

### 3. Initialize Knowledge Base
Seed the vector database with the latest MITRE ATT&CK Enterprise matrix:
```bash
pip install -r requirements.txt
python seed_database.py
```

### 4. Running the Dashboard
The dashboard is served at the root of the API:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000` in your browser.

## 🧠 Attribution Logic
The system identifies "clusters" by looking for shared behavioral nodes in the graph. 
- **Pivoting:** Analysts can query `/graph/actors-by-ttp/{mitre_id}` to find all actors using a specific technique across different reports.
- **Similarity:** The `/graph/clusters` endpoint calculates the "behavioral overlap" between actors, highlighting potential campaign links or shared tooling.

---
*Developed for Cyber Security Analysts to bridge the gap between raw text and structured intelligence.*
