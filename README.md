# PhishPipeline — Quick Start

## Production Deployment

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for the full step-by-step guide
(Railway backend + Vercel frontend + Chrome extension packaging).

Live URLs (fill in after deploying):

| Service | URL |
|---------|-----|
| Frontend | `https://<your-project>.vercel.app` |
| Backend API | `https://<your-backend>.up.railway.app` |
| API Docs | `https://<your-backend>.up.railway.app/docs` |

## Prerequisites
- Python 3.10+
- Node.js 18+
- Chrome (for extension)

## Run Everything

```bash
chmod +x start-all.sh
./start-all.sh
```

## Manual Start

```bash
# Backend
cd phishpipeline-backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd phishpipeline-dashboard
npm install && npm run dev
```

## Load Extension
1. Go to `chrome://extensions`
2. Enable Developer Mode
3. Click "Load unpacked"
4. Select the `phishpipeline-extension/` folder

## Environment Variables (phishpipeline-backend/.env)
- `PHISHPIPELINE_SKIP_MODEL_PRELOAD=1` — Use heuristic classifier
  (no HuggingFace download needed)
- `PHISHPIPELINE_SKIP_CERTSTREAM=1` — Disable CT log polling
- `GSB_API_KEY` — Google Safe Browsing API key (optional)
- `PHISHTANK_API_KEY` — PhishTank API key (optional)

## Endpoints
- `GET  /api/queue` — Live URL queue
- `POST /api/submit-url` — Submit a URL for classification
- `POST /api/ingest-domain` — Ingest from CT log
- `GET  /api/admin/flagged` — URLs pending admin review
- `POST /api/admin/label` — Label a URL as TP/FP
- `GET  /api/analytics/takedown` — Takedown analytics
- `GET  /api/reports` — Reporting status
- `GET  /docs` — Full API documentation (Swagger)
