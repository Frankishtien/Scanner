from flask_cors import CORS
from flask_restx import Api

# Flask extensions
cors = CORS()
api = Api(
    title='SecureCode AI API',
    version='1.0',
    description='Static Application Security Testing Platform API',
    doc='/api/docs',  # This should not conflict with root
    prefix='/api'     # Add prefix to all API routes
)

def init_extensions(app):
    """Initialize Flask extensions"""
    cors.init_app(app)
    api.init_app(app)
