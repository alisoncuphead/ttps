# CTI Analysis & Attribution Engine (TTP-AE)

## Project Overview
This project is an AI-powered intelligence platform designed to automate the extraction and synthesis of Cyber Threat Intelligence (CTI). By processing raw reports from URLs or files, the engine identifies actors, victims, IoCs, and TTPs, structuring them into a **Knowledge Graph** optimized for threat attribution, pivoting, and behavioral clustering.

### Core Vision
Transform static security reports into a dynamic, queryable graph where analysts can discover non-obvious links between disparate campaigns through shared behaviors (TTPs) and indicators.

---

## Technical Architecture
- **API & Orchestration:** FastAPI (Python 3.11)
- **Document Processing:** BeautifulSoup4 (Web), PyMuPDF (PDF)
- **Reasoning Engine:** Ollama (`deepseek-r1:8b` or `llama3`)
- **Semantic Mapping:** Qdrant (Vector DB for MITRE ATT&CK techniques)
- **Knowledge Graph:** Neo4j (Graph DB for attribution & pivoting)
- **Deployment:** Docker & Docker Compose

---

## Development Roadmap

### Sprint 1: Foundation & Semantic Grounding
*Goal: Establish the core infrastructure and the MITRE ATT&CK reference index.*
- [x] **Infrastructure:** Finalize `compose.yml` with Qdrant and Ollama services.
- [x] **Data Seeding:** Enhance `seed_database.py` to index the full MITRE Enterprise ATT&CK matrix into Qdrant.
- [x] **Project Scaffolding:** Create the `app/` directory structure and `main.py` entry point.
- [x] **Base API:** Implement health checks and basic configuration endpoints.

### Sprint 2: The Extraction Pipeline
*Goal: Successfully extract entities and summaries from raw CTI report URLs.*
- [x] **Acquisition Service:** Build a crawler capable of extracting clean text from HTML and PDF reports.
- [x] **LLM Prompt Engineering:** Design structured prompts for `deepseek-r1` to extract JSON-formatted summaries, actors, victims, and raw TTP descriptions.
- [x] **IoC Parser:** Implement regex or LLM-based extraction for IPs, domains, and hashes. (Handled via LLM extraction)

### Sprint 3: Behavioral Mapping (Grounding)
*Goal: Map "human-readable" TTP descriptions to official MITRE ATT&CK IDs.*
- [x] **Vector Search:** Implement a service to query Qdrant using embeddings of extracted TTP descriptions.
- [x] **Validation Layer:** Use the LLM to verify the top-k semantic matches against the report context to reduce false positives.
- [x] **Normalization:** Standardize all extracted entities (e.g., aliasing "APT28" to "Fancy Bear").

### Sprint 4: Knowledge Graph Ingestion
*Goal: Transform extracted data into a structured graph in Neo4j.*
- [x] **Ontology Definition:** Define nodes (`Report`, `Actor`, `Victim`, `TTP`, `Indicator`) and relationships (`USES`, `TARGETS`, `MENTIONS`).
- [x] **Graph Service:** Implement an ingestion pipeline that creates or updates nodes and edges based on extraction results.
- [x] **Neo4j Integration:** Add Neo4j to `compose.yml` and handle connection pooling.

### Sprint 5: Attribution & Analytics
*Goal: Enable analysts to pivot and cluster data for attribution.*
- [x] **Pivot API:** Create endpoints to query the graph (e.g., "Find all reports mentioning this TTP" or "Which actors target this industry?").
- [x] **Clustering Logic:** Implement graph-based clustering to group similar reports/actors based on shared infrastructure and behaviors.
- [x] **Basic UI/Dashboard:** A simple interface to visualize report summaries and graph relationships.

---

## Getting Started

### 1. Infrastructure Setup
```bash
docker-compose up -d
```

### 2. Initialize MITRE Index
```bash
pip install -r requirements.txt
python seed_database.py
```

### 3. Development
- All application logic resides in `app/`.
- Ensure `OLLAMA_HOST` and `QDRANT_HOST` are correctly set in your environment or `.env` file.

---

## Agent Development Mandates
- **Documentation:** Every file must contain a brief summary of its purpose and noteworthy features. Tag these summaries with `AIDEV`.
- **Context Retrieval:** Use `grep -r "AIDEV" .` to quickly gather architectural and functional context across the project.
- **Task Management:** Always update the task list in this file immediately after completing a task or sub-task.
- **Requirement Integrity:** If any aspect of the architecture or requirements is ambiguous, **stop and ask for clarification**. Never make assumptions about core functionality.
