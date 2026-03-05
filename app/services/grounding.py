"""
AIDEV: Grounding Service for TTP behavioral mapping.
Uses Qdrant vector search to map raw extracted TTP descriptions to
official MITRE ATT&CK techniques.
"""

import os
from typing import Any, Dict, List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http.models import FieldCondition, Filter, MatchValue
from sentence_transformers import SentenceTransformer


class GroundingService:
    def __init__(self):
        self.qdrant_host = os.getenv("QDRANT_HOST", "localhost")
        self.qdrant_port = int(os.getenv("QDRANT_PORT", 6333))
        self.collection_name = "mitre_attack"

        # Connect to Qdrant
        try:
            self.client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port)
        except Exception as e:
            print(f"[!] GroundingService: Could not connect to Qdrant: {e}")
            self.client = None

        # Small, efficient local embedding model
        self.model = SentenceTransformer("all-MiniLM-L6-v2")

    def find_matches(self, description: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Find the top-k MITRE techniques matching the behavior description."""
        if not self.client:
            return []

        vector = self.model.encode(description).tolist()

        try:
            search_result = self.client.search(
                collection_name=self.collection_name,
                query_vector=vector,
                limit=top_k,
                query_filter=Filter(
                    must=[
                        FieldCondition(key="type", match=MatchValue(value="technique"))
                    ]
                ),
            )

            matches = []
            for res in search_result:
                matches.append(
                    {
                        "technique_id": res.payload.get("technique_id"),
                        "name": res.payload.get("name"),
                        "score": res.score,
                        "description": res.payload.get("description"),
                    }
                )
            return matches
        except Exception as e:
            print(f"[!] Error during vector search: {e}")
            return []

    def find_actor(
        self, actor_name: str, score_threshold: float = 0.7
    ) -> Optional[Dict[str, Any]]:
        """Find the canonical MITRE actor name for a given alias."""
        if not self.client:
            return None

        vector = self.model.encode(f"Actor: {actor_name}").tolist()

        try:
            search_result = self.client.search(
                collection_name=self.collection_name,
                query_vector=vector,
                limit=1,
                query_filter=Filter(
                    must=[FieldCondition(key="type", match=MatchValue(value="actor"))]
                ),
            )

            if search_result and search_result[0].score >= score_threshold:
                res = search_result[0]
                return {
                    "name": res.payload.get("name"),
                    "aliases": res.payload.get("aliases"),
                    "score": res.score,
                }
            return None
        except Exception as e:
            print(f"[!] Error during actor normalization: {e}")
            return None


# Singleton instance
grounding_service = GroundingService()
