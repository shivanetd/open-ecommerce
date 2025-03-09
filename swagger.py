from flasgger import Swagger
from app import app

swagger = Swagger(app,
    template={
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
    })
