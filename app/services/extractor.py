"""
AIDEV: Extraction Service for CTI intelligence using LLMs.
Orchestrates structured prompts to Ollama (DeepSeek-R1) to extract:
Summaries, Actors, Victims, TTPs, and IoCs.
"""

import json
import os
from typing import Optional

import ollama

from app.models.extraction import ExtractionResult


class ExtractionService:
    def __init__(self):
        self.model = os.getenv("MODEL_NAME", "deepseek-r1:8b")
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.client = ollama.Client(host=self.host)

    def extract_intel(self, text: str) -> Optional[ExtractionResult]:
        """Send clean text to LLM and parse JSON response."""

        # Limit text length to prevent context overflow (conservative 12k chars)
        prompt_text = text[:12000]

        system_prompt = """
        You are an expert Cyber Threat Intelligence (CTI) analyst.
        Extract intelligence from the following security report.
        You MUST return the output as a JSON object with the following keys:
        - summary: A 2-3 sentence overview of the incident.
        - actors: A list of threat actor names (e.g., APT28). Return empty list if none.
        - victims: A list of organizations, industries, or countries targeted.
        - ttps: A list of objects with 'description' and 'context'. Each description should be a raw TTP behavior.
        - iocs: A list of objects with 'type' and 'value'. Include IPs, domains, hashes.

        Ensure the 'ttps' descriptions are behavioral (e.g., 'uses PowerShell to download a payload').
        
        REPORT TEXT:
        {text}
        """

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a CTI extraction engine that strictly outputs JSON.",
                    },
                    {"role": "user", "content": system_prompt.format(text=prompt_text)},
                ],
                format="json",
            )

            # Parse the JSON from the LLM response
            raw_json = json.loads(response["message"]["content"])
            return ExtractionResult(**raw_json)
        except Exception as e:
            print(f"[!] Error during LLM extraction: {e}")
            return None

    def validate_ttp(self, description: str, candidates: list) -> Optional[dict]:
        """Use LLM to select the best MITRE technique from candidates or reject all."""
        if not candidates:
            return None

        candidates_text = "\n".join(
            [
                f"ID: {c['technique_id']}, Name: {c['name']}, Description: {c['description'][:300]}..."
                for c in candidates
            ]
        )

        prompt = f"""
        Analyze the following behavioral description from a CTI report and select the most accurate MITRE ATT&CK technique from the provided candidates.
        
        BEHAVIORAL DESCRIPTION:
        "{description}"

        CANDIDATES:
        {candidates_text}

        Instructions:
        1. Select the technique that exactly matches the behavior.
        2. If none of the candidates are a strong match, return "None".
        3. Return ONLY a JSON object with the key 'best_id' (e.g., {{"best_id": "T1059.003"}}) or {{"best_id": "None"}}.

        Result:
        """

        try:
            response = self.client.chat(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a specialized CTI validator. Output strictly JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                format="json",
            )

            result = json.loads(response["message"]["content"])
            best_id = result.get("best_id")

            if best_id and best_id != "None":
                # Find the matching candidate object
                return next(
                    (c for c in candidates if c["technique_id"] == best_id), None
                )
            return None

        except Exception as e:
            print(f"[!] Error during TTP validation: {e}")
            return None


# Singleton instance for the app
extractor = ExtractionService()
