from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_restx import Api
import firebase_admin
from firebase_admin import credentials, firestore
import os

from .config import config
from .extensions import cors, api, init_extensions

def create_app(config_name=None):
    app = Flask(__name__, 
                static_folder='../../frontend',
                static_url_path='')
    
    # If no config specified, check environment or use development
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Load configuration
    app.config.from_object(config.get(config_name, config['default']))
    
    # Initialize extensions
    init_extensions(app)
    
    # Initialize Firebase
    if not firebase_admin._apps:
        cred_path = app.config.get('FIREBASE_CREDENTIALS', 'firebase-credentials.json')
        if os.path.exists(cred_path):
            try:
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
                app.db = firestore.client()
                print("Firebase initialized successfully")
            except Exception as e:
                print(f"Warning: Could not initialize Firebase: {e}")
                app.db = None
        else:
            print(f"Warning: Firebase credentials file not found at {cred_path}")
            app.db = None
    
    # Register API Blueprints
    from .api.routes.scan import scan_bp
    from .api.routes.reports import reports_bp
    from .api.routes.github import github_bp
    
    app.register_blueprint(scan_bp, url_prefix='/api/scan')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(github_bp, url_prefix='/api/github')
    
    # Serve frontend
    @app.route('/')
    def index():
        """Serve the frontend dashboard"""
        return send_from_directory('../../frontend', 'index.html')
    
    @app.route('/css/<path:path>')
    def serve_css(path):
        """Serve CSS files"""
        return send_from_directory('../../frontend/css', path)
    
    @app.route('/js/<path:path>')
    def serve_js(path):
        """Serve JavaScript files"""
        return send_from_directory('../../frontend/js', path)
    
    # API routes
    @app.route('/api/health')
    def health():
        return jsonify({
            'status': 'healthy',
            'database': 'connected' if app.db else 'disconnected',
            'environment': config_name
        })
    
    @app.route('/api')
    def api_info():
        return jsonify({
            'name': 'SecureCode AI API',
            'version': '1.0.0',
            'endpoints': {
                'scan': {
                    'upload': '/api/scan/upload (POST)',
                    'status': '/api/scan/status/<scan_id> (GET)',
                    'scanners': '/api/scan/scanners (GET)'
                },
                'github': {
                    'scan': '/api/github/scan (POST)'
                },
                'reports': {
                    'get': '/api/reports/<scan_id> (GET)',
                    'enriched': '/api/reports/<scan_id>/enriched (GET)',
                    'summary': '/api/reports/<scan_id>/summary (GET)'
                }
            },
            'documentation': '/api/docs'
        })
    
    return app
