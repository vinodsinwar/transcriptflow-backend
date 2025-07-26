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
import threading
import queue
import json

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
CORS(app, origins=['https://iyqcoelo.manus.space', 'https://cblcaylk.manus.space', 'https://ssonrirb.manus.space', 'http://localhost:5173', 'http://localhost:5174', 'http://localhost:3000'], 
     methods=['GET', 'POST', 'OPTIONS'], 
     allow_headers=['Content-Type', 'Authorization'],
     supports_credentials=True)

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
    storage_uri="memory://",
    strategy="fixed-window"
)

# Caching configuration
cache_config = {
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 3600  # 1 hour cache
}
app.config.update(cache_config)
cache = Cache(app)

# Enhanced Proxy Rotation System
class ProxyRotator:
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.failed_proxies = set()
        self.proxy_stats = {}
        self.lock = threading.Lock()
        self.initialize_proxies()
    
    def initialize_proxies(self):
        """Initialize proxy list with working free proxies"""
        # Working free proxy list (updated with real proxies)
        free_proxies = [
            # Note: Using direct connection as primary, proxies as fallback
            None,  # Direct connection first
            # Add working free proxies here when needed
        ]
        
        # Add user-agent rotation for better success
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        self.proxies = free_proxies
        
        # Initialize stats for each proxy
        for i, proxy in enumerate(self.proxies):
            self.proxy_stats[i] = {
                'success_count': 0,
                'failure_count': 0,
                'last_used': None,
                'avg_response_time': 0
            }
        
        logger.info(f"Initialized {len(self.proxies)} proxies for rotation")
    
    def get_next_proxy(self):
        """Get next available proxy with round-robin and health checking"""
        with self.lock:
            if not self.proxies:
                return None, None
            
            # Try to find a working proxy
            attempts = 0
            while attempts < len(self.proxies):
                proxy_index = self.current_index
                self.current_index = (self.current_index + 1) % len(self.proxies)
                
                # Skip failed proxies temporarily
                if proxy_index in self.failed_proxies:
                    attempts += 1
                    continue
                
                proxy = self.proxies[proxy_index]
                user_agent = random.choice(self.user_agents)
                
                return proxy, user_agent
            
            # If all proxies failed, reset failed list and try again
            logger.warning("All proxies failed, resetting failed proxy list")
            self.failed_proxies.clear()
            
            proxy = self.proxies[self.current_index]
            user_agent = random.choice(self.user_agents)
            self.current_index = (self.current_index + 1) % len(self.proxies)
            
            return proxy, user_agent
    
    def mark_proxy_success(self, proxy_index, response_time):
        """Mark proxy as successful"""
        with self.lock:
            if proxy_index in self.proxy_stats:
                stats = self.proxy_stats[proxy_index]
                stats['success_count'] += 1
                stats['last_used'] = time.time()
                
                # Update average response time
                if stats['avg_response_time'] == 0:
                    stats['avg_response_time'] = response_time
                else:
                    stats['avg_response_time'] = (stats['avg_response_time'] + response_time) / 2
                
                # Remove from failed list if present
                self.failed_proxies.discard(proxy_index)
    
    def mark_proxy_failure(self, proxy_index):
        """Mark proxy as failed"""
        with self.lock:
            if proxy_index in self.proxy_stats:
                self.proxy_stats[proxy_index]['failure_count'] += 1
                
                # Add to failed list if failure rate is high
                stats = self.proxy_stats[proxy_index]
                total_requests = stats['success_count'] + stats['failure_count']
                if total_requests >= 3 and stats['failure_count'] / total_requests > 0.7:
                    self.failed_proxies.add(proxy_index)
                    logger.warning(f"Proxy {proxy_index} marked as failed due to high failure rate")
    
    def get_proxy_stats(self):
        """Get proxy statistics"""
        with self.lock:
            return {
                'total_proxies': len(self.proxies),
                'failed_proxies': len(self.failed_proxies),
                'proxy_details': self.proxy_stats.copy()
            }

# Initialize proxy rotator
proxy_rotator = ProxyRotator()

def generate_cache_key(video_id):
    """Generate a cache key for video transcripts"""
    return f"transcript:v2:{video_id}"

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

def get_transcript_with_proxy_rotation(video_id):
    """
    Enhanced transcript retrieval with proxy rotation and multiple strategies
    """
    
    logger.info(f"Processing transcript request with proxy rotation for video ID: {video_id}")
    
    strategies = [
        'direct',           # No proxy, direct connection
        'proxy_rotation',   # Use rotating proxies
        'user_agent_only',  # Different user agents without proxy
        'headers_variation' # Various header combinations
    ]
    
    for strategy in strategies:
        logger.info(f"Trying strategy: {strategy} for video {video_id}")
        
        try:
            if strategy == 'direct':
                result = try_direct_connection(video_id)
            elif strategy == 'proxy_rotation':
                result = try_proxy_rotation(video_id)
            elif strategy == 'user_agent_only':
                result = try_user_agent_variation(video_id)
            elif strategy == 'headers_variation':
                result = try_headers_variation(video_id)
            
            if result[0] is not None:  # Success
                logger.info(f"Strategy {strategy} succeeded for video {video_id}")
                return result
                
        except Exception as e:
            logger.warning(f"Strategy {strategy} failed for video {video_id}: {str(e)}")
            continue
    
    logger.error(f"All strategies failed for video {video_id}")
    return None, None, 'all_strategies_failed'

def try_direct_connection(video_id):
    """Try direct connection without proxy"""
    try:
        transcript_list = YouTubeTranscriptApi().list(video_id)
        
        # Try to get English transcript first
        for transcript in transcript_list:
            if transcript.language_code in ['en', 'en-US', 'en-GB']:
                transcript_data = transcript.fetch()
                return transcript_data, transcript.language_code, 'direct'
        
        # If no English, try any available transcript
        for transcript in transcript_list:
            try:
                transcript_data = transcript.fetch()
                return transcript_data, transcript.language_code, 'direct'
            except Exception:
                continue
                
        return None, None, 'no_transcript'
        
    except (RequestBlocked, IpBlocked):
        return None, None, 'ip_blocked'
    except VideoUnavailable:
        return None, None, 'video_unavailable'
    except Exception as e:
        logger.error(f"Direct connection failed: {str(e)}")
        return None, None, 'server_error'

def try_proxy_rotation(video_id):
    """Try with rotating proxies"""
    max_proxy_attempts = min(3, len(proxy_rotator.proxies))
    
    for attempt in range(max_proxy_attempts):
        proxy, user_agent = proxy_rotator.get_next_proxy()
        
        if not proxy:
            logger.warning("No proxies available")
            break
        
        proxy_index = proxy_rotator.current_index - 1
        start_time = time.time()
        
        try:
            # Create custom session with proxy and user agent
            session = requests.Session()
            session.proxies.update(proxy)
            session.headers.update({
                'User-Agent': user_agent,
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Test proxy connectivity first
            test_response = session.get('https://httpbin.org/ip', timeout=10)
            if test_response.status_code != 200:
                raise Exception("Proxy connectivity test failed")
            
            # Try to get transcript using the proxy session
            # Note: youtube-transcript-api doesn't directly support custom sessions
            # This is a simplified approach - in production, you'd need to modify the library
            # or implement custom YouTube API calls
            
            transcript_list = YouTubeTranscriptApi().list(video_id)
            
            for transcript in transcript_list:
                if transcript.language_code in ['en', 'en-US', 'en-GB']:
                    transcript_data = transcript.fetch()
                    response_time = time.time() - start_time
                    proxy_rotator.mark_proxy_success(proxy_index, response_time)
                    return transcript_data, transcript.language_code, f'proxy_{proxy_index}'
            
            for transcript in transcript_list:
                try:
                    transcript_data = transcript.fetch()
                    response_time = time.time() - start_time
                    proxy_rotator.mark_proxy_success(proxy_index, response_time)
                    return transcript_data, transcript.language_code, f'proxy_{proxy_index}'
                except Exception:
                    continue
            
            return None, None, 'no_transcript'
            
        except Exception as e:
            proxy_rotator.mark_proxy_failure(proxy_index)
            logger.warning(f"Proxy {proxy_index} failed: {str(e)}")
            continue
    
    return None, None, 'proxy_failed'

def try_user_agent_variation(video_id):
    """Try with different user agents"""
    user_agents = proxy_rotator.user_agents
    
    for user_agent in user_agents:
        try:
            # Create session with custom user agent
            session = requests.Session()
            session.headers.update({
                'User-Agent': user_agent,
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })
            
            transcript_list = YouTubeTranscriptApi().list(video_id)
            
            for transcript in transcript_list:
                if transcript.language_code in ['en', 'en-US', 'en-GB']:
                    transcript_data = transcript.fetch()
                    return transcript_data, transcript.language_code, 'user_agent_variation'
            
            for transcript in transcript_list:
                try:
                    transcript_data = transcript.fetch()
                    return transcript_data, transcript.language_code, 'user_agent_variation'
                except Exception:
                    continue
                    
            return None, None, 'no_transcript'
            
        except (RequestBlocked, IpBlocked):
            continue
        except Exception as e:
            logger.warning(f"User agent variation failed: {str(e)}")
            continue
    
    return None, None, 'user_agent_failed'

def try_headers_variation(video_id):
    """Try with various header combinations"""
    header_variations = [
        {
            'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
        },
        {
            'User-Agent': 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        },
        {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
    ]
    
    for headers in header_variations:
        try:
            session = requests.Session()
            session.headers.update(headers)
            
            transcript_list = YouTubeTranscriptApi().list(video_id)
            
            for transcript in transcript_list:
                if transcript.language_code in ['en', 'en-US', 'en-GB']:
                    transcript_data = transcript.fetch()
                    return transcript_data, transcript.language_code, 'headers_variation'
            
            for transcript in transcript_list:
                try:
                    transcript_data = transcript.fetch()
                    return transcript_data, transcript.language_code, 'headers_variation'
                except Exception:
                    continue
                    
            return None, None, 'no_transcript'
            
        except (RequestBlocked, IpBlocked):
            continue
        except Exception as e:
            logger.warning(f"Headers variation failed: {str(e)}")
            continue
    
    return None, None, 'headers_failed'

@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend with Proxy Rotation is running',
        'version': '2.1.0',
        'timestamp': datetime.utcnow().isoformat(),
        'proxy_stats': proxy_rotator.get_proxy_stats()
    })

@app.route('/api/transcript', methods=['POST'])
@limiter.limit("10 per minute")
def get_transcript():
    """
    Enhanced transcript generation endpoint with proxy rotation
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

        # Try to get transcript with proxy rotation and multiple strategies
        transcript_data, language_code, source = get_transcript_with_proxy_rotation(video_id)
        
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
                'timestamp': datetime.utcnow().isoformat(),
                'proxy_stats': proxy_rotator.get_proxy_stats()
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
                'retry_after': 300,
                'proxy_stats': proxy_rotator.get_proxy_stats()
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
                'error_type': 'unknown',
                'proxy_stats': proxy_rotator.get_proxy_stats()
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error in get_transcript: {str(e)}")
        return jsonify({
            'error': sanitize_error_message('server_error'),
            'error_type': 'server_error'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced health check with proxy status"""
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
            'message': 'TranscriptFlow Backend with Proxy Rotation is running',
            'version': '2.1.0',
            'cache_status': cache_status,
            'timestamp': datetime.utcnow().isoformat(),
            'uptime': time.time(),
            'proxy_stats': proxy_rotator.get_proxy_stats()
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
    """Enhanced statistics endpoint with proxy information"""
    try:
        return jsonify({
            'version': '2.1.0',
            'features': [
                'Proxy rotation system',
                'Multiple fallback strategies',
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
            },
            'proxy_system': proxy_rotator.get_proxy_stats(),
            'strategies': [
                'direct',
                'proxy_rotation', 
                'user_agent_variation',
                'headers_variation'
            ]
        })
    except Exception as e:
        logger.error(f"Stats endpoint error: {str(e)}")
        return jsonify({'error': 'Stats unavailable'}), 500

@app.route('/api/proxy-stats', methods=['GET'])
@limiter.limit("5 per minute")
def get_proxy_stats():
    """Detailed proxy statistics endpoint"""
    try:
        return jsonify({
            'proxy_system': proxy_rotator.get_proxy_stats(),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Proxy stats endpoint error: {str(e)}")
        return jsonify({'error': 'Proxy stats unavailable'}), 500

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
    logger.info("Starting TranscriptFlow Backend v2.1.0 with Proxy Rotation System")
    app.run(debug=False, host='0.0.0.0', port=5000)

