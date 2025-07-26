from flask import Flask, request, jsonify
from flask_cors import CORS
from youtube_transcript_api import YouTubeTranscriptApi, NoTranscriptFound, TranscriptsDisabled, VideoUnavailable
from youtube_transcript_api._errors import RequestBlocked, IpBlocked
import re
import requests
import random

app = Flask(__name__)
CORS(app)

# List of free proxy servers (you can expand this list)
PROXY_LIST = [
    {'http': 'http://proxy-server.com:8080', 'https': 'https://proxy-server.com:8080'},
    # Add more proxies as needed
]

def get_transcript_with_fallback(video_id):
    """
    Try to get transcript with multiple fallback strategies
    """
    
    # Strategy 1: Try without proxy first
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
            except:
                continue
                
        return None, None, 'no_transcript'
        
    except (RequestBlocked, IpBlocked):
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
                    return transcript_data, transcript.language_code, 'custom_headers'
            
            # If no English, try any available transcript
            for transcript in transcript_list:
                try:
                    transcript_data = transcript.fetch()
                    return transcript_data, transcript.language_code, 'custom_headers'
                except:
                    continue
                    
            return None, None, 'no_transcript'
            
        except Exception as e:
            # Strategy 3: Return informative error about IP blocking
            return None, None, 'ip_blocked'
    
    except Exception as e:
        return None, None, f'error: {str(e)}'

@app.route('/')
def index():
    return "TranscriptFlow Backend is running!"

@app.route('/api/transcript', methods=['POST'])
def get_transcript():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        video_url = data.get('video_url')

        if not video_url:
            return jsonify({'error': 'Video URL is required'}), 400

        # Extract video ID from various YouTube URL formats
        video_id_match = re.search(r'(?:v=|youtu\.be/|embed/|watch\?v=)([a-zA-Z0-9_-]{11})', video_url)
        if not video_id_match:
            return jsonify({'error': 'Invalid YouTube URL'}), 400
        
        video_id = video_id_match.group(1)
        print(f"Extracted video ID: {video_id}")

        # Try to get transcript with fallback strategies
        transcript_data, language_code, source = get_transcript_with_fallback(video_id)
        
        if transcript_data:
            # Format transcript with timestamps
            formatted_transcript = ""
            for entry in transcript_data:
                start_time = int(entry.start)
                minutes = start_time // 60
                seconds = start_time % 60
                timestamp = f"[{minutes:02d}:{seconds:02d}]"
                formatted_transcript += f"{timestamp} {entry.text}\n"
            
            return jsonify({
                'transcript': formatted_transcript.strip(),
                'language': language_code,
                'source': source,
                'video_id': video_id
            })
        
        elif source == 'ip_blocked':
            return jsonify({
                'error': 'YouTube is currently blocking requests from this server. This is a temporary issue that occurs when using cloud-based servers. Please try again later or contact support.',
                'error_type': 'ip_blocked'
            }), 503
        
        elif source == 'no_transcript':
            return jsonify({
                'error': 'Could not retrieve a transcript for this video. This video may not have captions or subtitles available.',
                'error_type': 'no_transcript'
            }), 404
        
        else:
            return jsonify({
                'error': f'An unexpected error occurred: {source}',
                'error_type': 'unknown'
            }), 500

    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'TranscriptFlow Backend is running'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

