"""
AIDEV: Central Orchestrator for the TTP Extraction & Attribution Engine.
Coordinates data flow through the following pipeline:
1. Crawler (app/services/crawler.py) - URL content acquisition.
2. Extractor (app/services/extractor.py) - LLM-based entity & behavioral extraction.
3. Grounding (app/services/grounding.py) - Semantic mapping to MITRE ATT&CK.
4. Graph Store (app/services/graph_store.py) - Knowledge Graph ingestion in Neo4j.
Provides REST endpoints for analysis, graph pivoting, and behavioral clustering.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.models.extraction import AnalysisRequest, ExtractionResult
from app.services.crawler import crawler
from app.services.extractor import extractor
from app.services.graph_store import graph_store
from app.services.grounding import grounding_service

app = FastAPI(
    title="CTI Analysis & Attribution Engine",
    description="Automated Extraction and Attribution from CTI Reports",
    version="0.1.0",
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/")
async def read_root():
    """Serve the dashboard UI."""
    return FileResponse("app/static/index.html")


class HealthResponse(BaseModel):
    status: str
    version: str


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Verify that the API and basic services are reachable."""
    return HealthResponse(status="healthy", version="0.1.0")


@app.post("/analyze", response_model=ExtractionResult)
async def analyze_url(request: AnalysisRequest):
    """Fetch and extract intelligence from a CTI report URL."""

    # 1. Fetch and clean text
    raw_data = crawler.fetch_url(request.url)
    if not raw_data:
        raise HTTPException(status_code=400, detail="Could not fetch content from URL.")

    clean_text = crawler.extract_text(raw_data)
    if not clean_text:
        raise HTTPException(status_code=400, detail="No readable text found in report.")

    # 2. Extract intelligence using LLM
    result = extractor.extract_intel(clean_text)
    if not result:
        raise HTTPException(status_code=500, detail="LLM extraction failed.")

    # 2.5 Normalize Actor names
    normalized_actors = []
    for actor in result.actors:
        match = grounding_service.find_actor(actor)
        if match:
            normalized_actors.append(match["name"])
        else:
            normalized_actors.append(actor)
    # Deduplicate while preserving order
    result.actors = list(dict.fromkeys(normalized_actors))

    # 3. Ground and Validate TTPs to MITRE IDs
    for ttp in result.ttps:
        # Find top 3 candidates via vector search
        candidates = grounding_service.find_matches(ttp.description, top_k=3)
        if candidates:
            # Let LLM select the best candidate from the top 3
            validated_match = extractor.validate_ttp(ttp.description, candidates)
            if validated_match:
                ttp.mitre_id = validated_match["technique_id"]
                ttp.mitre_name = validated_match["name"]
                ttp.confidence = float(validated_match["score"])
            else:
                # If LLM rejects all top matches, fallback to the top vector match
                # with a lower confidence, or skip if confidence is too low.
                best_vector_match = candidates[0]
                if best_vector_match["score"] > 0.7:
                    ttp.mitre_id = best_vector_match["technique_id"]
                    ttp.mitre_name = best_vector_match["name"]
                    ttp.confidence = float(best_vector_match["score"])

    # 4. Ingest into Knowledge Graph
    try:
        graph_store.ingest_report(request.url, result)
    except Exception as e:
        # We don't fail the whole request if ingestion fails, but log it
        print(f"[!] Error during graph ingestion: {e}")

    return result


@app.get("/graph/actors-by-ttp/{mitre_id}")
async def actors_by_ttp(mitre_id: str):
    """Find actors using a specific TTP across all reports."""
    results = graph_store.get_actors_by_ttp(mitre_id)
    return {"ttp_id": mitre_id, "actors": results}


@app.get("/graph/reports-by-actor/{actor_name}")
async def reports_by_actor(actor_name: str):
    """Find reports mentioning a specific actor."""
    results = graph_store.get_related_reports(actor_name)
    return {"actor": actor_name, "reports": results}


@app.get("/graph/clusters")
async def actor_clusters(min_overlap: int = 1):
    """Identify clusters of actors that share common TTPs."""
    results = graph_store.get_actor_clusters(min_shared_ttps=min_overlap)
    return {"clusters": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
