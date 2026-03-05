"""
AIDEV: Knowledge Graph Service for CTI Entity Ingestion and Attribution Analytics.
- Ontology: Implements a core set of nodes (Report, Actor, Victim, TTP, Indicator) and relationships.
- Pivoting: Provides graph-traversal logic to find actors using specific TTPs or victims.
- Behavioral Clustering: Uses Cypher queries to quantify TTP overlap between threat actors,
  enabling analysts to identify campaign similarities that aren't visible through IoCs alone.
- Persistence: Managed via Neo4j using the bolt driver.
"""

import os
from typing import Optional

from neo4j import GraphDatabase

from app.models.extraction import ExtractionResult


class GraphStoreService:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "password")
        self.driver = None

        try:
            self.driver = GraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            self.driver.verify_connectivity()
        except Exception as e:
            print(f"[!] GraphStoreService: Could not connect to Neo4j: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def ingest_report(self, url: str, data: ExtractionResult):
        """Ingest extraction results into the Neo4j knowledge graph."""
        if not self.driver:
            return

        with self.driver.session() as session:
            session.execute_write(self._ingest_tx, url, data)

    @staticmethod
    def _ingest_tx(tx, url: str, data: ExtractionResult):
        # 1. Create Report Node
        tx.run(
            "MERGE (r:Report {url: $url}) SET r.summary = $summary, r.timestamp = timestamp()",
            url=url,
            summary=data.summary,
        )

        # 2. Ingest Actors
        for actor_name in data.actors:
            tx.run(
                """
                MERGE (a:Actor {name: $name})
                WITH a
                MATCH (r:Report {url: $url})
                MERGE (r)-[:MENTIONS]->(a)
            """,
                name=actor_name,
                url=url,
            )

        # 3. Ingest Victims
        for victim_name in data.victims:
            tx.run(
                """
                MERGE (v:Victim {name: $name})
                WITH v
                MATCH (r:Report {url: $url})
                MERGE (r)-[:MENTIONS]->(v)
                WITH v
                MATCH (a:Actor)-[:MENTIONS]-(r)
                MERGE (a)-[:TARGETS]->(v)
            """,
                name=victim_name,
                url=url,
            )

        # 4. Ingest TTPs (Grounded only)
        for ttp in data.ttps:
            if ttp.mitre_id:
                tx.run(
                    """
                    MERGE (t:TTP {mitre_id: $mitre_id})
                    SET t.name = $mitre_name
                    WITH t
                    MATCH (r:Report {url: $url})
                    MERGE (r)-[:MENTIONS]->(t)
                    WITH t
                    MATCH (a:Actor)-[:MENTIONS]-(r)
                    MERGE (a)-[:USES]->(t)
                """,
                    mitre_id=ttp.mitre_id,
                    mitre_name=ttp.mitre_name,
                    url=url,
                )

        # 5. Ingest IoCs
        for ioc in data.iocs:
            tx.run(
                """
                MERGE (i:Indicator {value: $value})
                SET i.type = $type
                WITH i
                MATCH (r:Report {url: $url})
                MERGE (i)-[:SEEN_IN]->(r)
            """,
                value=ioc.value,
                type=ioc.type,
                url=url,
            )

    def get_actors_by_ttp(self, mitre_id: str):
        """Find all actors that use a specific TTP (Technique ID)."""
        query = """
        MATCH (a:Actor)-[:USES]->(t:TTP {mitre_id: $mitre_id})
        RETURN a.name as actor_name, t.name as ttp_name
        """
        if not self.driver:
            return []
        with self.driver.session() as session:
            result = session.run(query, mitre_id=mitre_id)
            return [dict(record) for record in result]

    def get_related_reports(self, actor_name: str):
        """Find all reports that mention a specific actor."""
        query = """
        MATCH (r:Report)-[:MENTIONS]->(a:Actor {name: $actor_name})
        RETURN r.url as url, r.summary as summary
        """
        if not self.driver:
            return []
        with self.driver.session() as session:
            result = session.run(query, actor_name=actor_name)
            return [dict(record) for record in result]

    def get_actor_clusters(self, min_shared_ttps: int = 2):
        """
        Find clusters of actors that share common behaviors (TTPs).
        Returns pairs of actors and the count of TTPs they have in common.
        """
        query = """
        MATCH (a1:Actor)-[:USES]->(t:TTP)<-[:USES]-(a2:Actor)
        WHERE id(a1) < id(a2)
        WITH a1, a2, collect(t.name) as shared_ttps, count(t) as overlap
        WHERE overlap >= $min_shared_ttps
        RETURN a1.name as actor_1, a2.name as actor_2, shared_ttps, overlap
        ORDER BY overlap DESC
        """
        if not self.driver:
            return []
        with self.driver.session() as session:
            result = session.run(query, min_shared_ttps=min_shared_ttps)
            return [dict(record) for record in result]


# Singleton instance
graph_store = GraphStoreService()
