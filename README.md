---
title: TranscriptFlow Backend
emoji: 🎬
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# TranscriptFlow Backend

Flask API that powers [transcriptflow.io](https://transcriptflow.io) — generates transcripts for YouTube videos using `youtube-transcript-api`.

## Endpoints

- `GET /` — health check
- `GET /api/health` — detailed health check
- `POST /api/transcript` — body: `{"video_url": "https://www.youtube.com/watch?v=..."}`

## Configuration (env vars, all optional)

| Variable | Purpose |
|---|---|
| `WEBSHARE_PROXY_USERNAME` / `WEBSHARE_PROXY_PASSWORD` | Route YouTube requests through a Webshare rotating residential proxy |
| `GENERIC_PROXY_URL` | Route YouTube requests through any http(s) proxy (e.g. a self-hosted residential proxy) |
| `PORT` | Listen port when running `python src/main.py` directly (default 5000) |

## Run locally

```bash
pip install -r requirements.txt
python src/main.py
```

Or with Docker:

```bash
docker build -t transcriptflow-backend .
docker run -p 7860:7860 transcriptflow-backend
```
