from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import re
import logging
import threading
import time
from collections import OrderedDict
from datetime import datetime
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import (
    NoTranscriptFound,
    TranscriptsDisabled,
    VideoUnavailable,
    RequestBlocked,
    IpBlocked,
)
from youtube_transcript_api.formatters import SRTFormatter
from youtube_transcript_api.proxies import WebshareProxyConfig, GenericProxyConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Trust Render's reverse proxy so rate limiting sees the real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='memory://',
    headers_enabled=True,
)

ALLOWED_ORIGINS = [
    'https://transcriptflow.io',
    'https://www.transcriptflow.io',
    'https://transcriptflow-frontend.pages.dev',
    'http://localhost:5173',
    'http://localhost:4173',
    'http://localhost:3000',
]
CORS(app, origins=ALLOWED_ORIGINS, methods=['GET', 'POST', 'OPTIONS'], allow_headers=['Content-Type', 'Authorization'])


def _proxy_config_from_env():
    """Build an optional proxy config from environment variables.

    WEBSHARE_PROXY_USERNAME / WEBSHARE_PROXY_PASSWORD -> Webshare rotating residential proxy
    GENERIC_PROXY_URL -> any http(s) proxy (e.g. a self-hosted residential proxy)
    Neither set -> direct connection.
    """
    webshare_user = os.environ.get('WEBSHARE_PROXY_USERNAME')
    webshare_pass = os.environ.get('WEBSHARE_PROXY_PASSWORD')
    if webshare_user and webshare_pass:
        logger.info("Using Webshare proxy configuration")
        return WebshareProxyConfig(proxy_username=webshare_user, proxy_password=webshare_pass)

    generic_url = os.environ.get('GENERIC_PROXY_URL')
    if generic_url:
        logger.info("Using generic proxy configuration")
        return GenericProxyConfig(http_url=generic_url, https_url=generic_url)

    return None


PROXY_CONFIG = _proxy_config_from_env()

# In-memory LRU transcript cache. Repeat requests for the same video are
# served from here instead of re-fetching through the (paid) proxy.
CACHE_MAX_ENTRIES = int(os.environ.get('TRANSCRIPT_CACHE_MAX', 500))
CACHE_TTL_SECONDS = int(os.environ.get('TRANSCRIPT_CACHE_TTL', 24 * 3600))
_cache = OrderedDict()
_cache_lock = threading.Lock()


def cache_get(video_id):
    with _cache_lock:
        entry = _cache.get(video_id)
        if entry is None:
            return None
        stored_at, payload = entry
        if time.time() - stored_at > CACHE_TTL_SECONDS:
            del _cache[video_id]
            return None
        _cache.move_to_end(video_id)
        return dict(payload)


def cache_set(video_id, payload):
    with _cache_lock:
        _cache[video_id] = (time.time(), dict(payload))
        _cache.move_to_end(video_id)
        while len(_cache) > CACHE_MAX_ENTRIES:
            _cache.popitem(last=False)


def _fetch_transcript(video_id):
    """Fetch a transcript, preferring English, falling back to any available language.

    Returns (raw_entries, language_code).
    """
    ytt_api = YouTubeTranscriptApi(proxy_config=PROXY_CONFIG)
    try:
        fetched = ytt_api.fetch(video_id)
        return fetched, fetched.language_code
    except NoTranscriptFound:
        transcript_list = ytt_api.list(video_id)
        available = list(transcript_list)
        if not available:
            raise NoTranscriptFound(video_id, [], None)
        transcript = available[0]
        fetched = transcript.fetch()
        return fetched, transcript.language_code


@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend v3.1 is running',
        'version': '3.1.0',
        'proxy': 'configured' if PROXY_CONFIG else 'none',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/transcript', methods=['POST'])
@limiter.limit('10 per minute; 100 per hour')
def get_transcript():
    """Generate transcript from YouTube URL"""
    start_time = time.time()

    try:
        # Get request data
        data = request.get_json()
        if not data or not data.get('video_url'):
            return jsonify({
                'error': 'Invalid request. Please provide a video_url.',
                'error_type': 'invalid_input'
            }), 400

        video_url = data.get('video_url')

        # Extract video ID from URL. Only the ID is logged, never the full URL.
        video_id_match = re.search(r'(?:v=|youtu\.be/|embed/|watch\?v=)([a-zA-Z0-9_-]{11})', video_url)
        if not video_id_match:
            return jsonify({
                'error': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
                'error_type': 'invalid_url'
            }), 400

        video_id = video_id_match.group(1)
        logger.info(f"Processing transcript request for video {video_id}")

        # Serve repeat requests from cache to save proxy bandwidth
        cached = cache_get(video_id)
        if cached is not None:
            cached['cached'] = True
            cached['processing_time_ms'] = (time.time() - start_time) * 1000
            cached['timestamp'] = datetime.utcnow().isoformat()
            logger.info(f"Served video {video_id} from cache")
            return jsonify(cached)

        # Get transcript using youtube-transcript-api
        try:
            fetched_transcript, language_code = _fetch_transcript(video_id)

        except NoTranscriptFound:
            return jsonify({
                'error': 'No transcript available for this video. The video may not have captions or subtitles.',
                'error_type': 'no_transcript'
            }), 404

        except VideoUnavailable:
            return jsonify({
                'error': 'Video is not accessible. It may be private, deleted, or restricted.',
                'error_type': 'video_unavailable'
            }), 404

        except TranscriptsDisabled:
            return jsonify({
                'error': 'Transcripts are disabled for this video.',
                'error_type': 'transcripts_disabled'
            }), 404

        except (RequestBlocked, IpBlocked):
            logger.error(f"YouTube blocked the request for video {video_id} (server IP is blocked)")
            return jsonify({
                'error': 'YouTube is temporarily blocking requests from our server. Please try again in a few minutes.',
                'error_type': 'ip_blocked'
            }), 503

        except Exception as e:
            logger.error(f"Error fetching transcript: {str(e)}")
            return jsonify({
                'error': 'Failed to fetch transcript. Please try again later.',
                'error_type': 'fetch_error'
            }), 500

        # Format transcript with timestamps
        try:
            transcript_data = fetched_transcript.to_raw_data()

            formatted_transcript = ""
            for entry in transcript_data:
                start_time_seconds = int(entry['start'])
                minutes = start_time_seconds // 60
                seconds = start_time_seconds % 60
                timestamp = f"[{minutes:02d}:{seconds:02d}]"
                formatted_transcript += f"{timestamp} {entry['text']}\n"

            srt_content = SRTFormatter().format_transcript(fetched_transcript)
            word_count = sum(len(entry['text'].split()) for entry in transcript_data)
            last_entry = transcript_data[-1] if transcript_data else {'start': 0, 'duration': 0}
            duration_seconds = int(last_entry['start'] + last_entry.get('duration', 0))

            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000

            # Prepare response
            response_data = {
                'transcript': formatted_transcript.strip(),
                'language': language_code,
                'video_id': video_id,
                'word_count': word_count,
                'duration': duration_seconds,
                'srt': srt_content,
                'processing_time_ms': processing_time,
                'cached': False,
                'timestamp': datetime.utcnow().isoformat(),
                'success': True
            }

            cache_set(video_id, response_data)
            logger.info(f"Successfully processed transcript for video {video_id} in {processing_time:.2f}ms")
            return jsonify(response_data)

        except Exception as e:
            logger.error(f"Error formatting transcript: {str(e)}")
            return jsonify({
                'error': 'Error processing transcript data.',
                'error_type': 'format_error'
            }), 500

    except Exception as e:
        logger.error(f"Unexpected error in get_transcript: {str(e)}")
        return jsonify({
            'error': 'An unexpected error occurred. Please try again later.',
            'error_type': 'server_error'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Detailed health check"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend v3.1 is running',
        'version': '3.1.0',
        'timestamp': datetime.utcnow().isoformat(),
        'endpoints': [
            '/api/transcript (POST)',
            '/api/health (GET)'
        ]
    })

# Error handlers
@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({
        'error': 'Too many requests. Please wait a minute and try again.',
        'error_type': 'rate_limited'
    }), 429

@app.errorhandler(404)
def not_found_handler(e):
    return jsonify({
        'error': 'Endpoint not found',
        'error_type': 'not_found'
    }), 404

@app.errorhandler(500)
def internal_error_handler(e):
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({
        'error': 'Internal server error',
        'error_type': 'internal_error'
    }), 500

if __name__ == '__main__':
    logger.info("Starting TranscriptFlow Backend v3.1")
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
