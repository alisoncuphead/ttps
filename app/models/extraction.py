"""
AIDEV: Pydantic models for structured CTI extraction results.
Defines the schema for reports, actors, victims, IoCs, and TTPs.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class ExtractedTTP(BaseModel):
    description: str = Field(
        ..., description="Raw description of the behavior or technique from the report."
    )
    context: Optional[str] = Field(
        None, description="Additional context or evidence from the text."
    )
    mitre_id: Optional[str] = Field(
        None, description="Official MITRE ATT&CK Technique ID (e.g., T1059.003)."
    )
    mitre_name: Optional[str] = Field(
        None, description="Official MITRE ATT&CK Technique name."
    )
    confidence: Optional[float] = Field(
        None, description="Confidence score of the mapping."
    )


class ExtractedIOC(BaseModel):
    type: str = Field(..., description="Type of IoC (e.g., ip, domain, hash).")
    value: str = Field(..., description="The actual value of the indicator.")


class ExtractionResult(BaseModel):
    summary: str = Field(
        ..., description="A concise summary of the security incident or report."
    )
    actors: List[str] = Field(
        default_factory=list, description="List of suspected threat actors or groups."
    )
    victims: List[str] = Field(
        default_factory=list,
        description="List of targeted organizations, industries, or regions.",
    )
    ttps: List[ExtractedTTP] = Field(
        default_factory=list,
        description="List of raw TTP descriptions extracted from the text.",
    )
    iocs: List[ExtractedIOC] = Field(
        default_factory=list,
        description="List of indicators of compromise found in the report.",
    )


class AnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL of the CTI report to analyze.")
