#!/usr/bin/env python3
from app import create_app
import os

# Get environment from FLASK_ENV or default to development
env = os.environ.get('FLASK_ENV', 'development')
app = create_app(env)

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = app.config.get('DEBUG', True)
    
    app.run(host=host, port=port, debug=debug)
