# E-commerce Platform

A comprehensive Flask-based e-commerce platform with robust admin management capabilities.

## Features

- User Authentication & Authorization
- Product Management
- Shopping Cart Functionality
- Order Processing
- Admin Dashboard
- Dynamic Field Management
- RESTful API with Swagger Documentation

## Tech Stack

- Flask web framework
- MongoDB for database
- Bootstrap for admin UI
- Swagger/OpenAPI for documentation
- RESTful API design
- Role-based access control (admin/user)

## Installation

### Option 1: Local Installation

1. Clone the repository
```bash
git clone [your-repository-url]
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Set environment variables
```bash
export MONGODB_URI="your_mongodb_uri"
export JWT_SECRET_KEY="your_jwt_secret"
export FLASK_SECRET_KEY="your_flask_secret"
```

4. Run the application
```bash
python main.py
```

### Option 2: Using Docker

Pull and run the container from GitHub Container Registry:

```bash
# Pull the image
docker pull ghcr.io/[your-username]/[repository-name]:latest

# Run the container
docker run -d \
  -p 5000:5000 \
  -e MONGODB_URI="your_mongodb_uri" \
  -e JWT_SECRET_KEY="your_jwt_secret" \
  -e FLASK_SECRET_KEY="your_flask_secret" \
  ghcr.io/[your-username]/[repository-name]:latest
```

## API Documentation

Access the API documentation at `/docs` endpoint after starting the server.

## Admin Interface

Access the admin interface at `/admin/login`. Create an admin user through the registration endpoint with `is_admin=true`.