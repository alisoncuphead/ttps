import requests
import json
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer

# 1. Configuration
# We use the official MITRE STIX 2.1 data (Enterprise domain)
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
COLLECTION_NAME = "mitre_attack"

# Connect to your local Qdrant container
client = QdrantClient(host="localhost", port=6333)
# Small, efficient local embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')

def get_mitre_data():
    """Download and filter MITRE STIX data."""
    print(f"[*] Downloading MITRE STIX data from {MITRE_STIX_URL}...")
    response = requests.get(MITRE_STIX_URL)
    response.raise_for_status()
    data = response.json()
    
    # Filter for 'attack-pattern' objects (Techniques)
    # We ignore revoked or deprecated techniques to keep the data clean
    techniques = [
        obj for obj in data['objects'] 
        if obj['type'] == 'attack-pattern' and not obj.get('revoked', False)
    ]
    return techniques

def seed():
    techniques = get_mitre_data()
    print(f"[*] Found {len(techniques)} valid techniques. Preparing index...")

    # Recreate collection to ensure a clean slate
    client.recreate_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )

    points = []
    for i, t in enumerate(techniques):
        name = t.get('name')
        description = t.get('description', 'No description provided.')
        
        # Extract the official ATT&CK ID (e.g., T1059.003)
        external_refs = t.get('external_references', [])
        attack_id = next(
            (ref['external_id'] for ref in external_refs if ref.get('source_name') == 'mitre-attack'), 
            "Unknown"
        )

        # Create the vector using Name + Description for better context retrieval
        text_to_embed = f"{name}: {description[:1000]}"
        vector = model.encode(text_to_embed).tolist()

        points.append(PointStruct(
            id=i,
            vector=vector,
            payload={
                "name": name,
                "technique_id": attack_id,
                "description": description[:300] + "..." # Snippet for the UI
            }
        ))

    # Bulk upload for speed
    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"[+] Successfully indexed {len(points)} TTPs into Qdrant.")

if __name__ == "__main__":
    seed()
