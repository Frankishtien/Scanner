import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Firebase
    FIREBASE_CREDENTIALS = os.environ.get('FIREBASE_CREDENTIALS', 'firebase-credentials.json')
    
    # File upload
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/securecode_uploads')
    
    # Scanner settings
    SCANNER_TIMEOUT = int(os.environ.get('SCANNER_TIMEOUT', 300))
    MAX_REPO_SIZE = int(os.environ.get('MAX_REPO_SIZE', 100 * 1024 * 1024))
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'securecode.log')

class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

class ProductionConfig(Config):
    DEBUG = False
    # In production, require SECRET_KEY to be set
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        # Don't raise error during import, but log warning
        print("WARNING: SECRET_KEY not set in production environment!")
        SECRET_KEY = 'fallback-secret-key'  # Fallback to allow startup

class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SECRET_KEY = 'test-secret-key'

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig  # Use development as default
}
