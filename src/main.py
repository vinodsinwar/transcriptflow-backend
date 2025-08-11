from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import logging
import time
from datetime import datetime
from youtube_transcript_api import YouTubeTranscriptApi, NoTranscriptFound, TranscriptsDisabled, VideoUnavailable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enable CORS for all origins
CORS(app, origins=['*'], methods=['GET', 'POST', 'OPTIONS'], allow_headers=['Content-Type', 'Authorization'])

@app.route('/')
def index():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'TranscriptFlow Backend v3.0 is running',
        'version': '3.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/transcript', methods=['POST'])
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
        logger.info(f"Processing transcript request for URL: {video_url}")

        # Extract video ID from URL
        video_id_match = re.search(r'(?:v=|youtu\.be/|embed/|watch\?v=)([a-zA-Z0-9_-]{11})', video_url)
        if not video_id_match:
            return jsonify({
                'error': 'Invalid YouTube URL format. Please provide a valid YouTube video URL.',
                'error_type': 'invalid_url'
            }), 400
        
        video_id = video_id_match.group(1)
        logger.info(f"Extracted video ID: {video_id}")

        # Get transcript using youtube-transcript-api
        try:
            # Try direct approach first
            transcript_data = YouTubeTranscriptApi.get_transcript(video_id)
            language_code = 'auto-detected'
            
        except NoTranscriptFound:
            try:
                # Try to get available transcripts and pick the first one
                transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)
                available_transcripts = list(transcript_list)
                
                if not available_transcripts:
                    return jsonify({
                        'error': 'No transcript available for this video. The video may not have captions or subtitles.',
                        'error_type': 'no_transcript'
                    }), 404
                
                # Get the first available transcript
                transcript = available_transcripts[0]
                transcript_data = transcript.fetch()
                language_code = transcript.language_code
                
            except Exception as e:
                logger.error(f"Error getting transcript list: {str(e)}")
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
            
        except Exception as e:
            logger.error(f"Error fetching transcript: {str(e)}")
            return jsonify({
                'error': 'Failed to fetch transcript. Please try again later.',
                'error_type': 'fetch_error'
            }), 500

        # Format transcript with timestamps
        try:
            formatted_transcript = ""
            for entry in transcript_data:
                start_time_seconds = int(entry['start'])
                minutes = start_time_seconds // 60
                seconds = start_time_seconds % 60
                timestamp = f"[{minutes:02d}:{seconds:02d}]"
                formatted_transcript += f"{timestamp} {entry['text']}\n"
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000
            
            # Prepare response
            response_data = {
                'transcript': formatted_transcript.strip(),
                'language': language_code,
                'video_id': video_id,
                'processing_time_ms': processing_time,
                'cached': False,
                'timestamp': datetime.utcnow().isoformat(),
                'success': True
            }
            
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
        'message': 'TranscriptFlow Backend v3.0 is running',
        'version': '3.0.0',
        'timestamp': datetime.utcnow().isoformat(),
        'endpoints': [
            '/api/transcript (POST)',
            '/api/health (GET)'
        ]
    })

# Error handlers
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
    logger.info("Starting TranscriptFlow Backend v3.0")
    app.run(debug=False, host='0.0.0.0', port=5000)

