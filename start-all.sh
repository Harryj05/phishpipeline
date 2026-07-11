#!/bin/bash
echo "Starting PhishPipeline..."

# Terminal 1: Backend
cd phishpipeline-backend
pip install -r requirements.txt -q
PHISHPIPELINE_SKIP_MODEL_PRELOAD=0 \
PHISHPIPELINE_SKIP_CERTSTREAM=0 \
uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"
cd ..

# Wait for backend
sleep 3
echo "Backend health:"
curl -s http://localhost:8000/api/health | python3 -m json.tool

# Terminal 2: Frontend
cd phishpipeline-dashboard
npm install -q
npm run dev &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"
cd ..

echo ""
echo "✓ PhishPipeline running:"
echo "  Backend:   http://localhost:8000"
echo "  Frontend:  http://localhost:5173"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "To load extension in Chrome:"
echo "  chrome://extensions → Developer Mode → Load unpacked → phishpipeline-extension/"
echo ""
echo "Press Ctrl+C to stop all."
wait
