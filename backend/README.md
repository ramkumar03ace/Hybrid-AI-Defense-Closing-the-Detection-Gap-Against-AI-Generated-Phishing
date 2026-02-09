# Phishing Detection API

A FastAPI backend for detecting phishing emails using a fine-tuned DistilBERT model.

## Features

- **Single Email Analysis** - Analyze one email at a time
- **Batch Analysis** - Analyze multiple emails in one request
- **Confidence Scores** - Get probability scores for predictions
- **Risk Levels** - Automatic risk classification (LOW, MEDIUM, HIGH)

## Model Information

| Property | Value |
|----------|-------|
| Architecture | DistilBERT |
| Training Data | 9,600 emails (V2 dataset) |
| Test Accuracy | 99.17% |
| Precision | 98.92% |
| Recall | 99.35% |

## Project Structure

```
backend/
├── main.py                 # FastAPI application entry point
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── routers/
│   └── email_router.py     # API endpoints
├── services/
│   └── email_classifier.py # Model inference service
├── models/
│   └── schemas.py          # Pydantic request/response schemas
└── utils/
    └── text_preprocessor.py # Text cleaning utilities
```

## Installation

```bash
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt
```

## Running the Server

```bash
# Development mode with auto-reload
uvicorn main:app --reload

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

### Health Check
```
GET /api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "version": "1.0.0"
}
```

### Analyze Single Email
```
POST /api/v1/analyze
```

**Request:**
```json
{
  "text": "Dear Customer, Your account has been compromised. Click here to verify.",
  "subject": "Urgent: Account Security Alert"  // optional
}
```

**Response:**
```json
{
  "is_phishing": true,
  "confidence": 0.9977,
  "label": "PHISHING",
  "risk_level": "HIGH"
}
```

### Batch Analysis
```
POST /api/v1/batch
```

**Request:**
```json
{
  "emails": [
    {"text": "Email 1 content"},
    {"text": "Email 2 content"}
  ]
}
```

**Response:**
```json
{
  "results": [
    {"is_phishing": true, "confidence": 0.99, "label": "PHISHING", "risk_level": "HIGH"},
    {"is_phishing": false, "confidence": 0.85, "label": "LEGITIMATE", "risk_level": "LOW"}
  ],
  "total": 2,
  "phishing_count": 1,
  "legitimate_count": 1
}
```

## Interactive API Docs

Once the server is running, access:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Configuration

Edit `config.py` to customize:

| Setting | Default | Description |
|---------|---------|-------------|
| `MODEL_PATH` | `../model/saved_models/phishing_detector_model_v2` | Path to trained model |
| `MAX_TEXT_LENGTH` | 512 | Maximum tokens for input |
| `HIGH_RISK_THRESHOLD` | 0.85 | Confidence threshold for HIGH risk |
| `MEDIUM_RISK_THRESHOLD` | 0.50 | Confidence threshold for MEDIUM risk |

## Example Usage

### Python
```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/analyze",
    json={"text": "Your account needs verification. Click here."}
)
print(response.json())
```

### cURL
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{"text": "Your account needs verification. Click here."}'
```

### PowerShell
```powershell
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/analyze" `
  -Method Post -ContentType "application/json" `
  -Body '{"text": "Your account needs verification."}' `
  -UseBasicParsing | Select-Object -ExpandProperty Content
```

## License

MIT
