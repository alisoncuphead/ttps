import os
import json
import fitz  # PyMuPDF
from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
import ollama
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

app = FastAPI(title="TTP Extractor API")

# Initialize Local Services
client = QdrantClient("http://qdrant:6333")
embedder = SentenceTransformer('all-MiniLM-L6-v2')

class TTP(BaseModel):
    technique_id: str
    name: str
    evidence: str
    confidence: float

def extract_text_from_pdf(file_bytes):
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    return chr(12).join([page.get_text() for page in doc])

@app.post("/analyze", response_model=list[TTP])
async def analyze_document(file: UploadFile = File(...)):
    # 1. Parsing
    try:
        content = await file.read()
        if file.content_type == "application/pdf":
            text = extract_text_from_pdf(content)
        else:
            text = content.decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File parsing failed: {e}")

    # 2. Extract raw behaviors via Ollama (DeepSeek-R1)
    # Using a structured prompt to get specific behavioral quotes
    prompt = f"Analyze this report and list specific adversary behaviors. Return JSON only: {text[:4000]}"
    
    response = ollama.chat(
        model='deepseek-r1:8b',
        messages=[{'role': 'user', 'content': prompt}],
        format='json'
    )
    
    raw_findings = json.loads(response['message']['content'])

    # 3. Grounding/Validation via Qdrant
    validated_results = []
    for item in raw_findings.get('behaviors', []):
        description = item.get('description', '')
        vector = embedder.encode(description).tolist()
        
        search_result = client.search(
            collection_name="mitre_attack",
            query_vector=vector,
            limit=1
        )
        
        if search_result:
            match = search_result[0]
            validated_results.append(TTP(
                technique_id=match.payload['technique_id'],
                name=match.payload['name'],
                evidence=item.get('quote', description),
                confidence=match.score
            ))

    return validated_results
