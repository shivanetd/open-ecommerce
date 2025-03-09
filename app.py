import os
from flask import Flask, redirect, render_template
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from flask_cors import CORS
import logging
from mongoengine import connect

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'another-secret-key')  # For sessions
jwt = JWTManager(app)

# Configure MongoDB
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/ecommerce')
connect(host=MONGODB_URI)

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