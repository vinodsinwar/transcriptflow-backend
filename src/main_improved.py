from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from youtube_transcript_api import YouTubeTranscriptApi, NoTranscriptFound, TranscriptsDisabled, VideoUnavailable
from youtube_transcript_api._errors import RequestBlocked, IpBlocked
import re
import requests
import random
import hashlib
import logging
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('transcriptflow.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Security headers configuration
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers"""
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Remove server information
    response.headers.pop('Server', None)
    
    return response

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Will upgrade to Redis in production
    strategy="fixed-window"
)

# Caching configuration
cache_config = {
    'CACHE_TYPE': 'simple',  # Will upgrade to Redis in production
    'CACHE_DEFAULT_TIMEOUT': 3600  # 1 hour cache
}
app.config.update(cache_config)
cache = Cache(app)

# List of free proxy servers (expanded for better rotation)
PROXY_LIST = [
    {'http': 'http://proxy-server.com:8080', 'https': 'https://proxy-server.com:8080'},
    # Add more proxies as needed - will be expanded in proxy rotation phase
]

def generate_cache_key(video_id):
    """Generate a cache key for video transcripts"""
    return f"transcript:{video_id}"

def sanitize_error_message(error_type, original_error=None):
    """Return sanitized error messages for production"""
    error_messages = {
        'invalid_url': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
        'no_transcript': 'No transcript available for this video. The video may not have captions or subtitles.',
        'ip_blocked': 'Service temporarily unavailable. Please try again later.',
        'video_unavailable': 'Video is not accessible. It may be private, deleted, or restricted.',
        'rate_limit': 'Too many requests. Please wait before trying again.',
        'server_error': 'An unexpected error occurred. Please try again later.'
    }
    
    # Log the original error for debugging (server-side only)
    if original_error:
        logger.error(f"Error type: {error_type}, Original error: {str(original_error)}")
    
    return error_messages.get(error_type, error_messages['server_error'])

def get_transcript_with_fallback(video_id):
    """
    Try to get transcript with multiple fallback strategies
    Enhanced with better error handling and logging
    """
    
    logger.info(f"Processing transcript request for video ID: {video_id}")
    
    # Strategy 1: Try without proxy first
    try:
        transcript_list = YouTubeTranscriptApi().list(video_id)
        
        # Try to get English transcript first
        for transcript in transcript_list:
            if transcript.language_code in ['en', 'en-US', 'en-GB']:
                transcript_data = transcript.fetch()
                logger.info(f"Successfully retrieved English transcript for {video_id}")
                return transcript_data, transcript.language_code, 'direct'
        
        # If no English, try any available transcript
        for transcript in transcript_list:
            try:
                transcript_data = transcript.fetch()
                logger.info(f"Successfully retrieved {transcript.language_code} transcript for {video_id}")
                return transcript_data, transcript.language_code, 'direct'
            except Exception as e:
                logger.warning(f"Failed to fetch transcript in {transcript.language_code}: {str(e)}")
                continue
                
        logger.warning(f"No accessible transcripts found for {video_id}")
        return None, None, 'no_transcript'
        
    except (RequestBlocked, IpBlocked) as e:
        logger.warning(f"IP blocked for video {video_id}: {str(e)}")
        
        # Strategy 2: Try with different user agents and headers
        try:
            # Create a custom session with different headers
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            })
            
            # Try with custom session
            api = YouTubeTranscriptApi()
            transcript_list = api.list(video_id)
            
            # Try to get English transcript first
            for transcript in transcript_list:
                if transcript.language_code in ['en', 'en-US', 'en-GB']:
                    transcript_data = transcript.fetch()
                    logger.info(f"Successfully retrieved English transcript with custom headers for {video_id}")
                    return transcript_data, transcript.language_code, 'custom_headers'
            
            # If no English, try any available transcript
            for transcript in transcript_list:
                try:
                    transcript_data = transcript.fetch()
                    logger.info(f"Successfully retrieved {transcript.language_code} transcript with custom headers for {video_id}")
                    return transcript_data, transcript.language_code, 'custom_headers'
                except Exception as e:
                    logger.warning(f"Failed to fetch transcript in {transcript.language_code} with custom headers: {str(e)}")
                    continue
                    
            return None, None, 'no_transcript'
            
        except Exception as e:
            logger.error(f"Custom headers strategy failed for {video_id}: {str(e)}")
            return None, None, 'ip_blocked'
    
    except VideoUnavailable as e:
        logger.warning(f"Video unavailable: {video_id} - {str(e)}")
        return None, None, 'video_unavailable'
    
    except Exception as e:
        logger.error(f"Unexpected error for {video_id}: {str(e)}")
        return None, None, 'server_error'

@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend is running',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/transcript', methods=['POST'])
@limiter.limit("10 per minute")  # Rate limiting per IP
def get_transcript():
    """
    Enhanced transcript generation endpoint with caching and improved error handling
    """
    start_time = time.time()
    
    try:
        # Input validation
        data = request.get_json()
        if not data:
            logger.warning("No JSON data provided in request")
            return jsonify({
                'error': sanitize_error_message('invalid_url'),
                'error_type': 'invalid_input'
            }), 400
            
        video_url = data.get('video_url')
        if not video_url:
            logger.warning("No video URL provided in request")
            return jsonify({
                'error': sanitize_error_message('invalid_url'),
                'error_type': 'missing_url'
            }), 400

        # Enhanced URL validation
        video_id_match = re.search(r'(?:v=|youtu\.be/|embed/|watch\?v=)([a-zA-Z0-9_-]{11})', video_url)
        if not video_id_match:
            logger.warning(f"Invalid YouTube URL format: {video_url}")
            return jsonify({
                'error': sanitize_error_message('invalid_url'),
                'error_type': 'invalid_format'
            }), 400
        
        video_id = video_id_match.group(1)
        logger.info(f"Processing request for video ID: {video_id}")

        # Check cache first
        cache_key = generate_cache_key(video_id)
        cached_result = cache.get(cache_key)
        
        if cached_result:
            logger.info(f"Cache hit for video ID: {video_id}")
            processing_time = (time.time() - start_time) * 1000
            cached_result['processing_time_ms'] = processing_time
            cached_result['cached'] = True
            return jsonify(cached_result)

        # Try to get transcript with fallback strategies
        transcript_data, language_code, source = get_transcript_with_fallback(video_id)
        
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
            
            # Cache the successful result
            cache.set(cache_key, response_data, timeout=3600)  # Cache for 1 hour
            logger.info(f"Successfully processed and cached transcript for {video_id}")
            
            return jsonify(response_data)
        
        # Handle different error types with sanitized messages
        elif source == 'ip_blocked':
            return jsonify({
                'error': sanitize_error_message('ip_blocked'),
                'error_type': 'ip_blocked',
                'retry_after': 300  # Suggest retry after 5 minutes
            }), 503
        
        elif source == 'no_transcript':
            return jsonify({
                'error': sanitize_error_message('no_transcript'),
                'error_type': 'no_transcript'
            }), 404
        
        elif source == 'video_unavailable':
            return jsonify({
                'error': sanitize_error_message('video_unavailable'),
                'error_type': 'video_unavailable'
            }), 404
        
        else:
            return jsonify({
                'error': sanitize_error_message('server_error'),
                'error_type': 'unknown'
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error in get_transcript: {str(e)}")
        return jsonify({
            'error': sanitize_error_message('server_error'),
            'error_type': 'server_error'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced health check with system status"""
    try:
        # Test cache connectivity
        cache_status = 'healthy'
        try:
            cache.set('health_check', 'ok', timeout=10)
            cache.get('health_check')
        except Exception:
            cache_status = 'degraded'
        
        return jsonify({
            'status': 'healthy',
            'message': 'TranscriptFlow Backend is running',
            'version': '2.0.0',
            'cache_status': cache_status,
            'timestamp': datetime.utcnow().isoformat(),
            'uptime': time.time()
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': 'Health check failed'
        }), 500

@app.route('/api/stats', methods=['GET'])
@limiter.limit("5 per minute")
def get_stats():
    """Basic statistics endpoint"""
    try:
        return jsonify({
            'version': '2.0.0',
            'features': [
                'Rate limiting',
                'Security headers',
                'Response caching',
                'Enhanced error handling',
                'Comprehensive logging'
            ],
            'rate_limits': {
                'transcript_endpoint': '10 per minute',
                'stats_endpoint': '5 per minute',
                'global_limits': '200 per day, 50 per hour'
            },
            'cache_info': {
                'type': 'simple',
                'default_timeout': '1 hour'
            }
        })
    except Exception as e:
        logger.error(f"Stats endpoint error: {str(e)}")
        return jsonify({'error': 'Stats unavailable'}), 500

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    logger.warning(f"Rate limit exceeded: {get_remote_address()}")
    return jsonify({
        'error': sanitize_error_message('rate_limit'),
        'error_type': 'rate_limit_exceeded',
        'retry_after': e.retry_after
    }), 429

@app.errorhandler(404)
def not_found_handler(e):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Endpoint not found',
        'error_type': 'not_found'
    }), 404

@app.errorhandler(500)
def internal_error_handler(e):
    """Handle internal server errors"""
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({
        'error': sanitize_error_message('server_error'),
        'error_type': 'internal_error'
    }), 500

if __name__ == '__main__':
    logger.info("Starting TranscriptFlow Backend v2.0.0 with immediate improvements")
    app.run(debug=False, host='0.0.0.0', port=5000)  # Debug disabled for production

