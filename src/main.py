from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import io
import os
import re
import logging
import threading
import time
import requests
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
from youtube_transcript_api.formatters import SRTFormatter, WebVTTFormatter
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


class RotatingGenericProxyConfig(GenericProxyConfig):
    """GenericProxyConfig with retries: each retry goes through a fresh rotated IP,
    so a single blocked exit IP doesn't fail the whole request."""

    @property
    def retries_when_blocked(self):
        return int(os.environ.get('PROXY_RETRIES_WHEN_BLOCKED', 4))


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
        return RotatingGenericProxyConfig(http_url=generic_url, https_url=generic_url)

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


VIDEO_ID_RE = re.compile(r'(?:v=|youtu\.be/|embed/|watch\?v=)([a-zA-Z0-9_-]{11})')


def _video_id_from_url(video_url):
    match = VIDEO_ID_RE.search(video_url or '')
    return match.group(1) if match else None


def _get_video_title(video_id):
    """Best-effort video title via YouTube's public oEmbed endpoint (not IP-blocked)."""
    try:
        resp = requests.get(
            'https://www.youtube.com/oembed',
            params={'url': f'https://www.youtube.com/watch?v={video_id}', 'format': 'json'},
            timeout=5,
        )
        if resp.ok:
            return resp.json().get('title')
    except Exception:
        pass
    return None


def _pick_transcript(transcript_list):
    """Prefer a manually created transcript, then English, then whatever exists."""
    available = list(transcript_list)
    if not available:
        return None
    manual = [t for t in available if not t.is_generated]
    for pool in (manual, available):
        for t in pool:
            if t.language_code.startswith('en'):
                return t
    return (manual or available)[0]


class TranslationUnavailable(Exception):
    pass


def _fetch_transcript(video_id, target_language=None):
    """Fetch a transcript, optionally translated to target_language.

    Returns (fetched_transcript, language_code).
    """
    ytt_api = YouTubeTranscriptApi(proxy_config=PROXY_CONFIG)

    if target_language:
        transcript_list = ytt_api.list(video_id)
        transcript = _pick_transcript(transcript_list)
        if transcript is None:
            raise NoTranscriptFound(video_id, [], None)
        if transcript.language_code == target_language or transcript.language_code.split('-')[0] == target_language:
            fetched = transcript.fetch()
            return fetched, transcript.language_code
        if not transcript.is_translatable:
            raise TranslationUnavailable()
        codes = {tl.language_code for tl in transcript.translation_languages}
        if target_language not in codes:
            raise TranslationUnavailable()
        fetched = transcript.translate(target_language).fetch()
        return fetched, target_language

    try:
        fetched = ytt_api.fetch(video_id)
        return fetched, fetched.language_code
    except NoTranscriptFound:
        transcript_list = ytt_api.list(video_id)
        transcript = _pick_transcript(transcript_list)
        if transcript is None:
            raise NoTranscriptFound(video_id, [], None)
        fetched = transcript.fetch()
        return fetched, transcript.language_code


# Exceptions that mean "this video has no usable transcript" — never retry these.
_PERMANENT_ERRORS = (NoTranscriptFound, TranscriptsDisabled, VideoUnavailable, TranslationUnavailable)


def _fetch_with_retries(video_id, target_language=None, attempts=3):
    """Retry transient failures (blocked/captcha'd rotated proxy IPs get a fresh
    exit IP on each attempt); permanent no-transcript errors are raised immediately."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return _fetch_transcript(video_id, target_language)
        except _PERMANENT_ERRORS:
            raise
        except Exception as e:
            last_exc = e
            logger.warning(f"Transient fetch failure for video {video_id} (attempt {attempt + 1}/{attempts}): {type(e).__name__}")
    raise last_exc


def _transcript_payload(video_id, target_language=None):
    """Return (payload, was_cached) for a video, serving from the LRU cache when
    possible. Raises transcript errors on failure."""
    cache_key = f"{video_id}:{target_language or 'default'}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached, True

    fetched_transcript, language_code = _fetch_with_retries(video_id, target_language)
    transcript_data = fetched_transcript.to_raw_data()

    formatted_transcript = ""
    for entry in transcript_data:
        start_time_seconds = int(entry['start'])
        minutes = start_time_seconds // 60
        seconds = start_time_seconds % 60
        formatted_transcript += f"[{minutes:02d}:{seconds:02d}] {entry['text']}\n"

    srt_content = SRTFormatter().format_transcript(fetched_transcript)
    vtt_content = WebVTTFormatter().format_transcript(fetched_transcript)
    word_count = sum(len(entry['text'].split()) for entry in transcript_data)
    last_entry = transcript_data[-1] if transcript_data else {'start': 0, 'duration': 0}
    duration_seconds = int(last_entry['start'] + last_entry.get('duration', 0))
    video_title = _get_video_title(video_id)

    payload = {
        'transcript': formatted_transcript.strip(),
        'language': language_code,
        'video_id': video_id,
        'video_title': video_title,
        'word_count': word_count,
        'duration': duration_seconds,
        'srt': srt_content,
        'vtt': vtt_content,
        'cached': False,
        'success': True
    }
    cache_set(cache_key, payload)
    logger.info(f"Fetched and cached transcript for video {video_id} ({target_language or 'default'})")
    return payload, False


def _transcript_error_response(exc, video_id):
    """Map transcript exceptions to (json, status) responses; None if unhandled."""
    if isinstance(exc, TranslationUnavailable):
        return jsonify({
            'error': 'This transcript cannot be translated to the requested language.',
            'error_type': 'translation_unavailable'
        }), 400
    if isinstance(exc, NoTranscriptFound):
        return jsonify({
            'error': 'No transcript available for this video. The video may not have captions or subtitles.',
            'error_type': 'no_transcript'
        }), 404
    if isinstance(exc, VideoUnavailable):
        return jsonify({
            'error': 'Video is not accessible. It may be private, deleted, or restricted.',
            'error_type': 'video_unavailable'
        }), 404
    if isinstance(exc, TranscriptsDisabled):
        return jsonify({
            'error': 'Transcripts are disabled for this video.',
            'error_type': 'transcripts_disabled'
        }), 404
    if isinstance(exc, (RequestBlocked, IpBlocked)):
        logger.error(f"YouTube blocked the request for video {video_id} (server IP is blocked)")
        return jsonify({
            'error': 'YouTube is temporarily blocking requests from our server. Please try again in a few minutes.',
            'error_type': 'ip_blocked'
        }), 503
    return None


def _slugify(text):
    slug = re.sub(r'[^a-z0-9]+', '-', (text or '').lower()).strip('-')[:60]
    return slug or 'transcript'


FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fonts')
TIMESTAMP_LINE_RE = re.compile(r'^(\[\d+:\d{2}\])\s?(.*)$')


def _build_docx(payload):
    """Build a Word document of the transcript in memory."""
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    doc.add_heading(payload.get('video_title') or 'YouTube Video Transcript', level=1)
    meta = doc.add_paragraph()
    meta_run = meta.add_run(
        f"Language: {payload.get('language')}   •   Words: {payload.get('word_count')}   •   "
        f"Source: https://youtu.be/{payload.get('video_id')}   •   Generated by transcriptflow.io"
    )
    meta_run.font.size = Pt(9)

    for line in (payload.get('transcript') or '').split('\n'):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        match = TIMESTAMP_LINE_RE.match(line)
        if match:
            ts_run = p.add_run(match.group(1) + ' ')
            ts_run.bold = True
            p.add_run(match.group(2))
        else:
            p.add_run(line)

    buf = io.BytesIO()
    doc.save(buf)
    return buf


# Scripts that need extra fonts / text shaping in the PDF
_DEVANAGARI_RE = re.compile(r'[ऀ-ॿ]')
_ARABIC_RE = re.compile(r'[؀-ۿݐ-ݿࢠ-ࣿ]')
_COMPLEX_RE = re.compile(r'[֐-ࣿऀ-෿฀-໿ក-៿]')

# fontTools logs every subsetting step at INFO — silence it
logging.getLogger('fontTools').setLevel(logging.WARNING)


def _build_pdf(payload):
    """Build a PDF of the transcript in memory.

    Fast path for Latin-script transcripts (2 fonts, no shaping engine);
    extra fonts + HarfBuzz shaping only when the text actually needs them.
    """
    from fpdf import FPDF

    text_sample = f"{payload.get('video_title') or ''}\n{payload.get('transcript') or ''}"
    pdf = FPDF()
    pdf.add_font('NotoSans', '', os.path.join(FONT_DIR, 'NotoSans-Regular.ttf'))
    pdf.add_font('NotoSans', 'B', os.path.join(FONT_DIR, 'NotoSans-Bold.ttf'))

    fallbacks = []
    if _DEVANAGARI_RE.search(text_sample):
        pdf.add_font('NotoDeva', '', os.path.join(FONT_DIR, 'NotoSansDevanagari-Regular.ttf'))
        fallbacks.append('NotoDeva')
    if _ARABIC_RE.search(text_sample):
        pdf.add_font('NotoArab', '', os.path.join(FONT_DIR, 'NotoSansArabic-Regular.ttf'))
        fallbacks.append('NotoArab')
    if fallbacks:
        pdf.set_fallback_fonts(fallbacks)
    if _COMPLEX_RE.search(text_sample):
        try:
            # Proper shaping/BiDi for Arabic and Indic scripts (needs uharfbuzz)
            pdf.set_text_shaping(True)
        except Exception:
            pass

    pdf.set_auto_page_break(True, margin=18)
    pdf.add_page()
    pdf.set_font('NotoSans', 'B', 15)
    pdf.multi_cell(0, 8, payload.get('video_title') or 'YouTube Video Transcript', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(1)
    pdf.set_font('NotoSans', '', 9)
    pdf.set_text_color(120, 120, 120)
    pdf.multi_cell(
        0, 5.5,
        f"Language: {payload.get('language')}   •   Words: {payload.get('word_count')}   •   "
        f"Source: https://youtu.be/{payload.get('video_id')}   •   Generated by transcriptflow.io",
        new_x='LMARGIN', new_y='NEXT'
    )
    pdf.ln(3)
    pdf.set_text_color(20, 20, 20)
    pdf.set_font('NotoSans', '', 10.5)
    for line in (payload.get('transcript') or '').split('\n'):
        pdf.multi_cell(0, 6, line, new_x='LMARGIN', new_y='NEXT')

    return io.BytesIO(bytes(pdf.output()))


EXPORT_FORMATS = {
    'txt': ('text/plain', None),
    'docx': ('application/vnd.openxmlformats-officedocument.wordprocessingml.document', _build_docx),
    'pdf': ('application/pdf', _build_pdf),
}


@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend v3.3 is running',
        'version': '3.3.0',
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
        target_language = (data.get('target_language') or '').strip() or None
        if target_language and not re.fullmatch(r'[a-zA-Z-]{2,12}', target_language):
            return jsonify({
                'error': 'Invalid target language code.',
                'error_type': 'invalid_input'
            }), 400

        # Extract video ID from URL. Only the ID is logged, never the full URL.
        video_id = _video_id_from_url(video_url)
        if not video_id:
            return jsonify({
                'error': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
                'error_type': 'invalid_url'
            }), 400

        logger.info(f"Processing transcript request for video {video_id} (target_language={target_language})")

        try:
            payload, was_cached = _transcript_payload(video_id, target_language)
        except Exception as e:
            error_response = _transcript_error_response(e, video_id)
            if error_response:
                return error_response
            logger.error(f"Error fetching transcript: {str(e)}")
            return jsonify({
                'error': 'Failed to fetch transcript. Please try again later.',
                'error_type': 'fetch_error'
            }), 500

        payload['cached'] = was_cached
        payload['processing_time_ms'] = (time.time() - start_time) * 1000
        payload['timestamp'] = datetime.utcnow().isoformat()
        if was_cached:
            logger.info(f"Served video {video_id} from cache")
        return jsonify(payload)

    except Exception as e:
        logger.error(f"Unexpected error in get_transcript: {str(e)}")
        return jsonify({
            'error': 'An unexpected error occurred. Please try again later.',
            'error_type': 'server_error'
        }), 500


@app.route('/api/export', methods=['POST'])
@limiter.limit('10 per minute; 100 per hour')
def export_transcript():
    """Download the transcript as a TXT, Word (.docx), or PDF file."""
    try:
        data = request.get_json() or {}
        video_id = _video_id_from_url(data.get('video_url'))
        if not video_id:
            return jsonify({
                'error': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
                'error_type': 'invalid_url'
            }), 400

        export_format = (data.get('format') or '').lower().strip()
        if export_format not in EXPORT_FORMATS:
            return jsonify({
                'error': 'Invalid format. Supported formats: txt, docx, pdf.',
                'error_type': 'invalid_input'
            }), 400

        target_language = (data.get('target_language') or '').strip() or None
        if target_language and not re.fullmatch(r'[a-zA-Z-]{2,12}', target_language):
            return jsonify({
                'error': 'Invalid target language code.',
                'error_type': 'invalid_input'
            }), 400

        logger.info(f"Export request for video {video_id} as {export_format}")

        try:
            payload, _ = _transcript_payload(video_id, target_language)
        except Exception as e:
            error_response = _transcript_error_response(e, video_id)
            if error_response:
                return error_response
            logger.error(f"Error fetching transcript for export: {str(e)}")
            return jsonify({
                'error': 'Failed to fetch transcript. Please try again later.',
                'error_type': 'fetch_error'
            }), 500

        mimetype, builder = EXPORT_FORMATS[export_format]
        filename = f"{_slugify(payload.get('video_title') or video_id)}.{export_format}"

        # Generated files are cached so repeat downloads are instant
        file_cache_key = f"export:{video_id}:{target_language or 'default'}:{export_format}"
        cached_file = cache_get(file_cache_key)
        if cached_file is not None:
            return send_file(io.BytesIO(cached_file['bytes']), mimetype=mimetype,
                             as_attachment=True, download_name=filename)

        if builder is None:
            buf = io.BytesIO((payload.get('transcript') or '').encode('utf-8'))
        else:
            buf = builder(payload)
        buf.seek(0)
        cache_set(file_cache_key, {'bytes': buf.getvalue()})
        return send_file(buf, mimetype=mimetype, as_attachment=True, download_name=filename)

    except Exception as e:
        logger.error(f"Unexpected error in export_transcript: {str(e)}")
        return jsonify({
            'error': 'An unexpected error occurred. Please try again later.',
            'error_type': 'server_error'
        }), 500


@app.route('/api/languages', methods=['POST'])
@limiter.limit('10 per minute; 100 per hour')
def get_languages():
    """List available transcript languages and translation targets for a video."""
    try:
        data = request.get_json()
        video_id = _video_id_from_url((data or {}).get('video_url'))
        if not video_id:
            return jsonify({
                'error': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
                'error_type': 'invalid_url'
            }), 400

        cache_key = f"langs:{video_id}"
        cached = cache_get(cache_key)
        if cached is not None:
            return jsonify(cached)

        try:
            ytt_api = YouTubeTranscriptApi(proxy_config=PROXY_CONFIG)
            transcript_list = ytt_api.list(video_id)
            transcripts = [
                {
                    'language': t.language,
                    'language_code': t.language_code,
                    'is_generated': t.is_generated,
                }
                for t in transcript_list
            ]
            picked = _pick_transcript(ytt_api.list(video_id))
            translation_languages = [
                {'language': tl.language, 'language_code': tl.language_code}
                for tl in (picked.translation_languages if picked and picked.is_translatable else [])
            ]
        except (TranscriptsDisabled, VideoUnavailable, NoTranscriptFound):
            return jsonify({
                'error': 'No transcript available for this video.',
                'error_type': 'no_transcript'
            }), 404
        except (RequestBlocked, IpBlocked):
            return jsonify({
                'error': 'YouTube is temporarily blocking requests from our server. Please try again in a few minutes.',
                'error_type': 'ip_blocked'
            }), 503

        response_data = {
            'video_id': video_id,
            'transcripts': transcripts,
            'translation_languages': translation_languages,
            'success': True,
        }
        cache_set(cache_key, response_data)
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Unexpected error in get_languages: {str(e)}")
        return jsonify({
            'error': 'An unexpected error occurred. Please try again later.',
            'error_type': 'server_error'
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Detailed health check"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend v3.3 is running',
        'version': '3.3.0',
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
    logger.info("Starting TranscriptFlow Backend v3.3")
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
