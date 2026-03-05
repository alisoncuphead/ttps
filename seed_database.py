"""
AIDEV: Seed script for the MITRE ATT&CK knowledge base.
Downloads STIX 2.1 data and indexes Techniques (TTPs) and Actors (Intrusion Sets)
into Qdrant for semantic search and grounding.
"""

import json
import os

import requests
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

# 1. Configuration
# We use the official MITRE STIX 2.1 data (Enterprise domain)
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
COLLECTION_NAME = "mitre_attack"

# Environment-aware configuration
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))

# Connect to your local Qdrant container
try:
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
except Exception as e:
    print(f"[!] Could not connect to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}: {e}")
    exit(1)

# Small, efficient local embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")


def get_mitre_data():
    """Download and filter MITRE STIX data."""
    print(f"[*] Downloading MITRE STIX data from {MITRE_STIX_URL}...")
    try:
        response = requests.get(MITRE_STIX_URL, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[!] Error downloading MITRE data: {e}")
        return None


def process_techniques(data):
    """Extract and prepare techniques (TTPs)."""
    techniques = [
        obj
        for obj in data["objects"]
        if obj["type"] == "attack-pattern" and not obj.get("revoked", False)
    ]

    points = []
    for i, t in enumerate(techniques):
        name = t.get("name")
        description = t.get("description", "No description provided.")

        # Extract the official ATT&CK ID (e.g., T1059.003)
        external_refs = t.get("external_references", [])
        attack_id = next(
            (
                ref["external_id"]
                for ref in external_refs
                if ref.get("source_name") == "mitre-attack"
            ),
            "Unknown",
        )

        # Extract Tactics
        kill_chain_phases = t.get("kill_chain_phases", [])
        tactics = [
            phase["phase_name"]
            for phase in kill_chain_phases
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # Create the vector using Name + Description for better context retrieval
        text_to_embed = f"{name}: {description[:1000]}"
        vector = model.encode(text_to_embed).tolist()

        points.append(
            PointStruct(
                id=i,
                vector=vector,
                payload={
                    "type": "technique",
                    "name": name,
                    "technique_id": attack_id,
                    "tactics": tactics,
                    "description": description[:500] + "...",
                },
            )
        )
    return points


def process_actors(data, start_id):
    """Extract and prepare actors (Intrusion Sets)."""
    actors = [
        obj
        for obj in data["objects"]
        if obj["type"] == "intrusion-set" and not obj.get("revoked", False)
    ]

    points = []
    for i, a in enumerate(actors):
        name = a.get("name")
        description = a.get("description", "No description provided.")
        aliases = a.get("aliases", [])

        # Create the vector using Name + Aliases + Description
        text_to_embed = (
            f"Actor: {name}. Aliases: {', '.join(aliases)}. {description[:800]}"
        )
        vector = model.encode(text_to_embed).tolist()

        points.append(
            PointStruct(
                id=start_id + i,
                vector=vector,
                payload={
                    "type": "actor",
                    "name": name,
                    "aliases": aliases,
                    "description": description[:500] + "...",
                },
            )
        )
    return points


def seed():
    data = get_mitre_data()
    if not data:
        return

    tech_points = process_techniques(data)
    actor_points = process_actors(data, len(tech_points))
    all_points = tech_points + actor_points

    print(
        f"[*] Found {len(tech_points)} techniques and {len(actor_points)} actors. Preparing Qdrant index..."
    )

    # Recreate collection to ensure a clean slate
    try:
        client.recreate_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE),
        )

        # Bulk upload for speed
        client.upsert(collection_name=COLLECTION_NAME, points=all_points)
        print(f"[+] Successfully indexed {len(all_points)} MITRE objects into Qdrant.")
    except Exception as e:
        print(f"[!] Error indexing into Qdrant: {e}")


if __name__ == "__main__":
    seed()
