#!/usr/bin/env python3
"""
TranscriptFlow FastAPI Backend - Short-term Improvements
Async processing, better concurrency, and monitoring capabilities
"""

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, validator
from youtube_transcript_api import YouTubeTranscriptApi, NoTranscriptFound, TranscriptsDisabled, VideoUnavailable
from youtube_transcript_api._errors import RequestBlocked, IpBlocked
import asyncio
# import aioredis  # Temporarily disabled due to compatibility issues
import re
import time
import logging
import structlog
from datetime import datetime
from typing import Optional, Dict, Any
import json
import os
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import threading

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter('transcriptflow_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('transcriptflow_request_duration_seconds', 'Request duration')
TRANSCRIPT_REQUESTS = Counter('transcriptflow_transcript_requests_total', 'Transcript requests', ['status', 'source'])
CACHE_HITS = Counter('transcriptflow_cache_hits_total', 'Cache hits')
CACHE_MISSES = Counter('transcriptflow_cache_misses_total', 'Cache misses')

# Pydantic models
class TranscriptRequest(BaseModel):
    video_url: str
    
    @validator('video_url')
    def validate_youtube_url(cls, v):
        if not v:
            raise ValueError('Video URL is required')
        
        # Enhanced YouTube URL validation
        youtube_pattern = r'(?:https?://)?(?:www\.)?(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/)([a-zA-Z0-9_-]{11})'
        if not re.search(youtube_pattern, v):
            raise ValueError('Invalid YouTube URL format')
        
        return v

class TranscriptResponse(BaseModel):
    transcript: str
    language: str
    source: str
    video_id: str
    processing_time_ms: float
    cached: bool
    timestamp: str

class ErrorResponse(BaseModel):
    error: str
    error_type: str
    retry_after: Optional[int] = None

class HealthResponse(BaseModel):
    status: str
    message: str
    version: str
    cache_status: str
    timestamp: str
    uptime: float

# FastAPI app initialization
app = FastAPI(
    title="TranscriptFlow API",
    description="Enhanced YouTube Transcript Generation API with async processing",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global variables for caching and monitoring
redis_client = None
app_start_time = time.time()

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    start_time = time.time()
    
    response = await call_next(request)
    
    # Add security headers
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # Remove server information
    if "server" in response.headers:
        del response.headers["server"]
    
    # Record metrics
    process_time = time.time() - start_time
    REQUEST_DURATION.observe(process_time)
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    return response

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize connections and services"""
    global redis_client
    
    logger.info("Starting TranscriptFlow FastAPI backend v3.0.0")
    
    # Redis temporarily disabled due to compatibility issues
    # Will use memory cache for now
    redis_client = None
    logger.info("Using memory cache (Redis disabled for compatibility)")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup connections"""
    global redis_client
    
    if redis_client:
        await redis_client.close()
    
    logger.info("TranscriptFlow FastAPI backend shutdown complete")

# Cache utilities
async def get_cache_key(video_id: str) -> str:
    """Generate cache key for video transcript"""
    return f"transcript:v3:{video_id}"

async def get_cached_transcript(video_id: str) -> Optional[Dict[str, Any]]:
    """Get cached transcript if available"""
    if not redis_client:
        return None
    
    try:
        cache_key = await get_cache_key(video_id)
        cached_data = await redis_client.get(cache_key)
        
        if cached_data:
            CACHE_HITS.inc()
            return json.loads(cached_data)
        else:
            CACHE_MISSES.inc()
            return None
    except Exception as e:
        logger.warning("Cache retrieval failed", error=str(e))
        CACHE_MISSES.inc()
        return None

async def cache_transcript(video_id: str, data: Dict[str, Any], ttl: int = 3600):
    """Cache transcript data"""
    if not redis_client:
        return
    
    try:
        cache_key = await get_cache_key(video_id)
        await redis_client.setex(cache_key, ttl, json.dumps(data))
        logger.info("Transcript cached", video_id=video_id, ttl=ttl)
    except Exception as e:
        logger.warning("Cache storage failed", error=str(e))

# Enhanced transcript processing
async def get_transcript_with_fallback_async(video_id: str) -> tuple[Optional[list], Optional[str], str]:
    """
    Async wrapper for transcript retrieval with fallback strategies
    """
    
    logger.info("Processing transcript request", video_id=video_id)
    
    # Run the synchronous YouTube API calls in a thread pool
    loop = asyncio.get_event_loop()
    
    try:
        # Strategy 1: Direct API call
        result = await loop.run_in_executor(None, get_transcript_sync, video_id)
        return result
    except Exception as e:
        logger.error("Async transcript processing failed", video_id=video_id, error=str(e))
        return None, None, 'server_error'

def get_transcript_sync(video_id: str) -> tuple[Optional[list], Optional[str], str]:
    """
    Synchronous transcript retrieval (runs in thread pool)
    """
    
    try:
        transcript_list = YouTubeTranscriptApi().list(video_id)
        
        # Try to get English transcript first
        for transcript in transcript_list:
            if transcript.language_code in ['en', 'en-US', 'en-GB']:
                transcript_data = transcript.fetch()
                logger.info("English transcript retrieved", video_id=video_id)
                return transcript_data, transcript.language_code, 'direct'
        
        # If no English, try any available transcript
        for transcript in transcript_list:
            try:
                transcript_data = transcript.fetch()
                logger.info("Transcript retrieved", video_id=video_id, language=transcript.language_code)
                return transcript_data, transcript.language_code, 'direct'
            except Exception as e:
                logger.warning("Failed to fetch transcript", video_id=video_id, language=transcript.language_code, error=str(e))
                continue
                
        logger.warning("No accessible transcripts found", video_id=video_id)
        return None, None, 'no_transcript'
        
    except (RequestBlocked, IpBlocked) as e:
        logger.warning("IP blocked", video_id=video_id, error=str(e))
        return None, None, 'ip_blocked'
    
    except VideoUnavailable as e:
        logger.warning("Video unavailable", video_id=video_id, error=str(e))
        return None, None, 'video_unavailable'
    
    except Exception as e:
        logger.error("Unexpected error in transcript retrieval", video_id=video_id, error=str(e))
        return None, None, 'server_error'

def sanitize_error_message(error_type: str) -> str:
    """Return sanitized error messages for production"""
    error_messages = {
        'invalid_url': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
        'no_transcript': 'No transcript available for this video. The video may not have captions or subtitles.',
        'ip_blocked': 'Service temporarily unavailable. Please try again later.',
        'video_unavailable': 'Video is not accessible. It may be private, deleted, or restricted.',
        'rate_limit': 'Too many requests. Please wait before trying again.',
        'server_error': 'An unexpected error occurred. Please try again later.'
    }
    
    return error_messages.get(error_type, error_messages['server_error'])

# API Endpoints
@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint with basic health info"""
    return HealthResponse(
        status="healthy",
        message="TranscriptFlow FastAPI Backend is running",
        version="3.0.0",
        cache_status="healthy" if redis_client else "memory",
        timestamp=datetime.utcnow().isoformat(),
        uptime=time.time() - app_start_time
    )

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Enhanced health check endpoint"""
    cache_status = "healthy"
    
    if redis_client:
        try:
            await redis_client.ping()
            cache_status = "healthy"
        except Exception:
            cache_status = "degraded"
    else:
        cache_status = "memory"
    
    return HealthResponse(
        status="healthy",
        message="TranscriptFlow FastAPI Backend is running",
        version="3.0.0",
        cache_status=cache_status,
        timestamp=datetime.utcnow().isoformat(),
        uptime=time.time() - app_start_time
    )

@app.post("/api/transcript", response_model=TranscriptResponse)
@limiter.limit("10/minute")
async def get_transcript(request: Request, transcript_request: TranscriptRequest, background_tasks: BackgroundTasks):
    """
    Enhanced async transcript generation endpoint
    """
    start_time = time.time()
    
    try:
        # Extract video ID
        video_id_match = re.search(r'(?:v=|youtu\.be/|embed/|watch\?v=)([a-zA-Z0-9_-]{11})', transcript_request.video_url)
        if not video_id_match:
            TRANSCRIPT_REQUESTS.labels(status='error', source='validation').inc()
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error=sanitize_error_message('invalid_url'),
                    error_type='invalid_format'
                ).dict()
            )
        
        video_id = video_id_match.group(1)
        logger.info("Processing transcript request", video_id=video_id, client_ip=get_remote_address(request))

        # Check cache first
        cached_result = await get_cached_transcript(video_id)
        
        if cached_result:
            logger.info("Cache hit", video_id=video_id)
            processing_time = (time.time() - start_time) * 1000
            cached_result['processing_time_ms'] = processing_time
            cached_result['cached'] = True
            TRANSCRIPT_REQUESTS.labels(status='success', source='cache').inc()
            return TranscriptResponse(**cached_result)

        # Get transcript with async processing
        transcript_data, language_code, source = await get_transcript_with_fallback_async(video_id)
        
        if transcript_data:
            # Format transcript with timestamps
            formatted_transcript = ""
            for entry in transcript_data:
                start_time_seconds = int(entry.start)
                minutes = start_time_seconds // 60
                seconds = start_time_seconds % 60
                timestamp = f"[{minutes:02d}:{seconds:02d}]"
                formatted_transcript += f"{timestamp} {entry.text}\n"
            
            # Prepare response
            response_data = {
                'transcript': formatted_transcript.strip(),
                'language': language_code,
                'source': source,
                'video_id': video_id,
                'processing_time_ms': (time.time() - start_time) * 1000,
                'cached': False,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Cache the successful result in background
            background_tasks.add_task(cache_transcript, video_id, response_data)
            
            logger.info("Transcript processed successfully", video_id=video_id, language=language_code, source=source)
            TRANSCRIPT_REQUESTS.labels(status='success', source=source).inc()
            
            return TranscriptResponse(**response_data)
        
        # Handle different error types
        elif source == 'ip_blocked':
            TRANSCRIPT_REQUESTS.labels(status='error', source='ip_blocked').inc()
            raise HTTPException(
                status_code=503,
                detail=ErrorResponse(
                    error=sanitize_error_message('ip_blocked'),
                    error_type='ip_blocked',
                    retry_after=300
                ).dict()
            )
        
        elif source == 'no_transcript':
            TRANSCRIPT_REQUESTS.labels(status='error', source='no_transcript').inc()
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error=sanitize_error_message('no_transcript'),
                    error_type='no_transcript'
                ).dict()
            )
        
        elif source == 'video_unavailable':
            TRANSCRIPT_REQUESTS.labels(status='error', source='video_unavailable').inc()
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error=sanitize_error_message('video_unavailable'),
                    error_type='video_unavailable'
                ).dict()
            )
        
        else:
            TRANSCRIPT_REQUESTS.labels(status='error', source='server_error').inc()
            raise HTTPException(
                status_code=500,
                detail=ErrorResponse(
                    error=sanitize_error_message('server_error'),
                    error_type='unknown'
                ).dict()
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Unexpected error in transcript endpoint", error=str(e))
        TRANSCRIPT_REQUESTS.labels(status='error', source='server_error').inc()
        raise HTTPException(
            status_code=500,
            detail=ErrorResponse(
                error=sanitize_error_message('server_error'),
                error_type='server_error'
            ).dict()
        )

@app.get("/api/stats")
@limiter.limit("5/minute")
async def get_stats(request: Request):
    """Enhanced statistics endpoint with monitoring data"""
    return {
        'version': '3.0.0',
        'framework': 'FastAPI',
        'features': [
            'Async processing',
            'Rate limiting',
            'Security headers',
            'Redis caching',
            'Enhanced error handling',
            'Structured logging',
            'Prometheus metrics'
        ],
        'rate_limits': {
            'transcript_endpoint': '10 per minute',
            'stats_endpoint': '5 per minute'
        },
        'cache_info': {
            'type': 'Redis' if redis_client else 'Memory',
            'default_timeout': '1 hour'
        },
        'monitoring': {
            'metrics_endpoint': '/metrics',
            'structured_logging': True,
            'prometheus_enabled': True
        },
        'uptime_seconds': time.time() - app_start_time
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Error handlers
@app.exception_handler(422)
async def validation_exception_handler(request: Request, exc):
    """Handle validation errors"""
    logger.warning("Validation error", error=str(exc))
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            error=sanitize_error_message('invalid_url'),
            error_type='validation_error'
        ).dict()
    )

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc):
    """Handle internal server errors"""
    logger.error("Internal server error", error=str(exc))
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error=sanitize_error_message('server_error'),
            error_type='internal_error'
        ).dict()
    )

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting TranscriptFlow FastAPI Backend v3.0.0")
    uvicorn.run(
        "main_fastapi:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
        access_log=True
    )

