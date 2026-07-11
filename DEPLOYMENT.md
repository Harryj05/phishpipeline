# PhishPipeline — Production Deployment Guide

## Step 1: Deploy Backend to Railway

1. Go to https://railway.app and sign up (free tier works)

2. Click "New Project" → "Deploy from GitHub repo"
   - Connect your GitHub account if not connected
   - Select the PhishPipeline repository
   - Set the **root directory** to: `phishpipeline-backend`

3. Railway will auto-detect the Dockerfile and start building.

4. Once deployed, go to **Settings → Networking → Generate Domain**
   This gives you a URL like: `https://phishpipeline-backend.up.railway.app`
   Copy this URL — you'll need it for Steps 2 and 3.

5. Go to **Variables** tab and add:

   ```
   DATABASE_PATH=/data/phishpipeline.db
   PHISHPIPELINE_SKIP_CERTSTREAM=0
   PHISHPIPELINE_SKIP_TAKEDOWN_TRACKER=0
   ALLOWED_ORIGINS_REGEX=^(https://phishpipeline\.vercel\.app|chrome-extension://.*)$
   ```

   Replace `phishpipeline.vercel.app` with your actual Vercel URL (add after Step 2).

6. Go to **Volumes** tab → Add Volume:
   - Mount path: `/data`

   This makes the SQLite database persist across deploys.

7. Verify the backend is live:

   ```bash
   curl https://your-railway-url.up.railway.app/api/health
   ```

   Should return: `{"status":"ok","models_loaded":false,"db":"ok"}`


## Step 2: Deploy Frontend to Vercel

1. Go to https://vercel.com and sign up (free)

2. Click "Add New Project" → Import from GitHub
   - Select the PhishPipeline repository
   - Set **Root Directory** to: `phishpipeline-dashboard`
   - Framework preset: **Vite** (auto-detected)

3. Before deploying, go to **Environment Variables** and add:

   ```
   VITE_API_URL = https://your-railway-url.up.railway.app
   ```

   (Use the Railway URL from Step 1)

4. Click **Deploy**. Vercel builds and deploys automatically.
   Your URL will be something like: `https://phishpipeline.vercel.app`

5. Go back to Railway → Variables and update ALLOWED_ORIGINS_REGEX
   to include your actual Vercel URL:

   ```
   ALLOWED_ORIGINS_REGEX=^(https://phishpipeline\.vercel\.app|chrome-extension://.*)$
   ```

   Railway will auto-redeploy.

6. Verify: Open your Vercel URL in the browser.
   The green dot in the nav should appear after ~3 seconds.


## Step 3: Update and Reload Extension

1. Open `phishpipeline-extension/popup.js`
   Replace `PRODUCTION_URL` with your actual Railway URL:

   ```js
   const PRODUCTION_URL = "https://your-railway-url.up.railway.app";
   ```

2. Open `phishpipeline-extension/background.js`
   Make the same replacement for `PRODUCTION_URL`.

3. Open `phishpipeline-extension/manifest.json`
   In `host_permissions`, replace the placeholder:

   ```json
   "https://your-railway-url.up.railway.app/*"
   ```

4. Run the build script:

   ```bash
   cd phishpipeline-extension
   ./build.sh
   ```

5. In Chrome, go to `chrome://extensions`
   - If extension already loaded: click ↺ refresh button
   - If loading fresh: click "Load unpacked" → select `dist/` folder

6. Click the PhishPipeline shield in your Chrome toolbar.
   The dot should turn green (connected to Railway backend).


## Step 4: Seed Demo Data

Once backend and frontend are deployed, seed the demo data:

```bash
cd phishpipeline-backend
python -c "
import seed_demo
seed_demo.BASE = 'https://your-railway-url.up.railway.app'
seed_demo.seed()
"
```

Or simply edit the `BASE` variable in `seed_demo.py` and run:
`python seed_demo.py`


## URLs After Deployment

| Service | URL |
|---------|-----|
| Frontend | https://phishpipeline.vercel.app |
| Backend API | https://your-railway-url.up.railway.app |
| API Docs | https://your-railway-url.up.railway.app/docs |
| Health Check | https://your-railway-url.up.railway.app/api/health |


## Updating After Code Changes

**Frontend:** Push to GitHub → Vercel auto-deploys (< 2 min)

**Backend:** Push to GitHub → Railway auto-deploys (< 5 min)

**Extension:** Re-run `./build.sh` → Reload in chrome://extensions


## Troubleshooting

| Issue | Fix |
|-------|-----|
| Dashboard shows "Backend Offline" | Check Railway deploy logs; verify ALLOWED_ORIGINS_REGEX includes Vercel URL |
| Extension shows red dot | Verify PRODUCTION_URL in popup.js matches Railway URL exactly |
| Railway deploy fails | Check Dockerfile builds locally first: `docker build .` |
| Vercel build fails | Run `npm run build` locally and fix errors first |
| Database resets on redeploy | Ensure Railway Volume is mounted at /data |
| CORS error in console | Update ALLOWED_ORIGINS_REGEX in Railway variables |
