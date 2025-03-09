import os
from flask import Flask, redirect, render_template
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from flask_cors import CORS
import logging
from mongoengine import connect, disconnect
from urllib.parse import quote_plus
import traceback

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'another-secret-key')  # For sessions
jwt = JWTManager(app)

# Configure MongoDB - Close existing connections first
disconnect()
# Get MongoDB URI from environment and ensure password is properly encoded
MONGODB_URI = os.environ.get('MONGODB_URI')
if not MONGODB_URI:
    logger.error("MONGODB_URI environment variable is not set")
    raise ValueError("MONGODB_URI environment variable is required")

try:
    # Connect to MongoDB
    logger.info(f"Attempting to connect to MongoDB...")
    connect(host=MONGODB_URI)
    logger.info("Successfully connected to MongoDB")

    # Test the connection by making a simple query
    from models import User
    test_count = User.objects.count()
    logger.info(f"Connection test successful. Found {test_count} users in database.")

except Exception as e:
    logger.error(f"Error connecting to MongoDB: {str(e)}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    raise

# Configure Swagger
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

template = {
    "swagger": "2.0",
    "info": {
        "title": "E-commerce API",
        "description": "A Flask-based e-commerce REST API",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\""
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

swagger = Swagger(app, config=swagger_config, template=template)

# Root route
@app.route('/')
def index():
    """Redirect to API documentation"""
    return redirect('/docs')

# Import routes after app initialization
from auth import auth_bp
from products import products_bp
from cart import cart_bp
from admin import admin_bp

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(products_bp)
app.register_blueprint(cart_bp)
app.register_blueprint(admin_bp)