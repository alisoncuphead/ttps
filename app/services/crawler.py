"""
AIDEV: Acquisition Service (Crawler) for CTI reports.
Handles fetching and text extraction from HTML (BeautifulSoup4) and PDF (PyMuPDF) URLs.
Provides clean, segmented text for LLM processing.
"""

import io
from typing import Any, Dict, Optional

import fitz  # PyMuPDF
import requests
from bs4 import BeautifulSoup


class AcquisitionService:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

    def fetch_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch content from URL and determine type."""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "").lower()
            return {
                "content": response.content,
                "content_type": content_type,
                "url": url,
            }
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return None

    def extract_text(self, raw_data: Dict[str, Any]) -> str:
        """Entry point for text extraction based on content type."""
        content_type = raw_data["content_type"]

        if "application/pdf" in content_type or raw_data["url"].endswith(".pdf"):
            return self._extract_from_pdf(raw_data["content"])
        else:
            return self._extract_from_html(raw_data["content"])

    def _extract_from_html(self, content: bytes) -> str:
        """Extract and clean text from HTML content."""
        soup = BeautifulSoup(content, "html.parser")

        # Remove noise
        for element in soup(["script", "style", "nav", "footer", "header", "aside"]):
            element.decompose()

        # Get text and clean whitespace
        text = soup.get_text(separator="\n")
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        return "\n".join(chunk for chunk in chunks if chunk)

    def _extract_from_pdf(self, content: bytes) -> str:
        """Extract text from PDF using PyMuPDF."""
        text = ""
        try:
            with fitz.open(stream=io.BytesIO(content), filetype="pdf") as doc:
                for page in doc:
                    text += page.get_text()
        except Exception as e:
            print(f"[!] Error processing PDF: {e}")
        return text


# Singleton instance for the app
crawler = AcquisitionService()
