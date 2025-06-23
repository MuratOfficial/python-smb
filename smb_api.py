#!/usr/bin/env python3
"""
SMB REST API Service
A Flask-based REST API for SMB file operations with signing support.
"""

import os
import json
import logging
import tempfile
import base64
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
import argparse

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not found. Install with: pip install python-dotenv")
    print("Environment variables will be loaded from system environment only.")

try:
    from flask import Flask, request, jsonify, send_file
    from werkzeug.utils import secure_filename
    from werkzeug.exceptions import BadRequest
except ImportError:
    print("Error: Flask not found. Install with: pip install flask")
    exit(1)

# Import our SMB service
try:
    from smb_service import SMBFileService, SMBConfig, load_config_from_env, load_config_from_file
except ImportError:
    print("Error: smb_service.py not found. Make sure it's in the same directory.")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Global SMB service instance
smb_service = None

def init_smb_service_from_env():
    """Initialize SMB service from environment variables"""
    global smb_service
    try:
        config = load_config_from_env()
        smb_service = SMBFileService(config)
        logger.info("SMB service initialized from environment variables")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize SMB service from environment: {e}")
        return False

def init_smb_service_from_config(config_path: str):
    """Initialize SMB service from config file"""
    global smb_service
    try:
        config = load_config_from_file(config_path)
        smb_service = SMBFileService(config)
        logger.info(f"SMB service initialized from config file: {config_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize SMB service from config file: {e}")
        return False

def require_smb_service():
    """Decorator to ensure SMB service is initialized"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if smb_service is None:
                return jsonify({
                    'status': 'error',
                    'error': 'SMB service not initialized'
                }), 500
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'SMB REST API',
        'timestamp': datetime.now().isoformat(),
        'smb_initialized': smb_service is not None
    })

@app.route('/smb/test', methods=['GET'])
@require_smb_service()
def test_connection():
    """Test SMB connection"""
    try:
        result = smb_service.test_connection()
        status_code = 200 if result['status'] == 'success' else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Connection test error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/smb/files', methods=['GET'])
@require_smb_service()
def list_files():
    """List files in remote directory"""
    try:
        remote_path = request.args.get('path', '')
        result = smb_service.list_files(remote_path)
        status_code = 200 if result['status'] == 'success' else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"List files error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/smb/upload', methods=['POST'])
@require_smb_service()
def upload_file():
    """Upload file to SMB share"""
    try:
        # Check if file or base64 data is provided
        file_data = None
        filename = None
        
        if 'file' in request.files:
            # Handle multipart file upload
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'error': 'No file selected'
                }), 400
            
            filename = secure_filename(file.filename)
            file_data = file.read()
            
        elif request.is_json:
            # Handle JSON with base64 encoded file
            data = request.get_json()
            if 'file_data' not in data or 'filename' not in data:
                return jsonify({
                    'status': 'error',
                    'error': 'JSON upload requires file_data (base64) and filename fields'
                }), 400
            
            try:
                file_data = base64.b64decode(data['file_data'])
                filename = secure_filename(data['filename'])
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'error': f'Invalid base64 data: {str(e)}'
                }), 400
        else:
            return jsonify({
                'status': 'error',
                'error': 'No file data provided'
            }), 400
        
        # Get remote path
        if 'file' in request.files:
            remote_path = request.form.get('remote_path', filename)
            create_dirs = request.form.get('create_dirs', 'true').lower() == 'true'
        else:
            data = request.get_json()
            remote_path = data.get('remote_path', filename)
            create_dirs = data.get('create_dirs', True)
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(file_data)
            temp_path = temp_file.name
        
        try:
            # Upload to SMB
            result = smb_service.upload_file(temp_path, remote_path, create_dirs)
            status_code = 200 if result['status'] == 'success' else 400
            return jsonify(result), status_code
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Failed to delete temp file: {e}")
                
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/smb/download', methods=['GET', 'POST'])
@require_smb_service()
def download_file():
    """Download file from SMB share"""
    try:
        # Get remote path from query params (GET) or JSON body (POST)
        if request.method == 'GET':
            remote_path = request.args.get('path')
            return_file = request.args.get('return_file', 'false').lower() == 'true'
        else:
            data = request.get_json()
            if not data or 'remote_path' not in data:
                return jsonify({
                    'status': 'error',
                    'error': 'remote_path is required'
                }), 400
            remote_path = data['remote_path']
            return_file = data.get('return_file', False)
        
        if not remote_path:
            return jsonify({
                'status': 'error',
                'error': 'remote_path parameter is required'
            }), 400
        
        # Create temporary file for download
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_path = temp_file.name
        temp_file.close()
        
        try:
            # Download from SMB
            result = smb_service.download_file(remote_path, temp_path, overwrite=True)
            
            if result['status'] != 'success':
                return jsonify(result), 400
            
            if return_file:
                # Return file directly
                filename = Path(remote_path).name
                return send_file(
                    temp_path,
                    as_attachment=True,
                    download_name=filename,
                    mimetype='application/octet-stream'
                )
            else:
                # Return base64 encoded file content
                with open(temp_path, 'rb') as f:
                    file_content = base64.b64encode(f.read()).decode('utf-8')
                
                result['file_data'] = file_content
                result['encoding'] = 'base64'
                return jsonify(result), 200
                
        finally:
            # Clean up temp file (unless returning it directly)
            if not return_file:
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file: {e}")
                    
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/smb/delete', methods=['DELETE', 'POST'])
@require_smb_service()
def delete_file():
    """Delete file from SMB share"""
    try:
        # Get remote path from query params (DELETE) or JSON body (POST)
        if request.method == 'DELETE':
            remote_path = request.args.get('path')
        else:
            data = request.get_json()
            if not data or 'remote_path' not in data:
                return jsonify({
                    'status': 'error',
                    'error': 'remote_path is required'
                }), 400
            remote_path = data['remote_path']
        
        if not remote_path:
            return jsonify({
                'status': 'error',
                'error': 'remote_path parameter is required'
            }), 400
        
        # We need to add delete functionality to the SMB service
        # For now, return not implemented
        return jsonify({
            'status': 'error',
            'error': 'Delete functionality not yet implemented in SMB service'
        }), 501
        
    except Exception as e:
        logger.error(f"Delete error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/smb/mkdir', methods=['POST'])
@require_smb_service()
def create_directory():
    """Create directory on SMB share"""
    try:
        data = request.get_json()
        if not data or 'remote_path' not in data:
            return jsonify({
                'status': 'error',
                'error': 'remote_path is required'
            }), 400
        
        remote_path = data['remote_path']
        
        # Use the internal method to create directory
        full_remote_path = f"{smb_service.server_url}/{remote_path.lstrip('/')}"
        smb_service._ensure_remote_dir(full_remote_path)
        
        return jsonify({
            'status': 'success',
            'remote_path': full_remote_path,
            'message': 'Directory created successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Create directory error: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.errorhandler(413)
def file_too_large(e):
    return jsonify({
        'status': 'error',
        'error': 'File too large. Maximum size is 100MB.'
    }), 413

@app.errorhandler(400)
def bad_request(e):
    return jsonify({
        'status': 'error',
        'error': 'Bad request'
    }), 400

@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'status': 'error',
        'error': 'Internal server error'
    }), 500

def main():
    """Main function to run the Flask app"""
    parser = argparse.ArgumentParser(description='SMB REST API Server')
    parser.add_argument('--config', '-c', help='SMB configuration file (JSON)')
    parser.add_argument('--env', action='store_true', help='Load configuration from environment variables')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Initialize SMB service
    logger.info("Initializing SMB service...")
    
    if args.env:
        # Load from environment variables
        if not init_smb_service_from_env():
            logger.error("Failed to initialize SMB service from environment. Exiting.")
            exit(1)
    elif args.config:
        # Load from config file
        if not init_smb_service_from_config(args.config):
            logger.error("Failed to initialize SMB service from config file. Exiting.")
            exit(1)
    else:
        # Try environment first, then fail
        logger.info("No config file specified, trying environment variables...")
        if not init_smb_service_from_env():
            logger.error("Failed to initialize SMB service. Please provide --config file or set environment variables.")
            exit(1)
    
    # Start Flask app
    logger.info(f"Starting SMB REST API server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()