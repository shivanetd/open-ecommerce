from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from models import User
from mongoengine.errors import NotUniqueError, ValidationError
from functools import wraps

auth_bp = Blueprint('auth', __name__)

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        try:
            user = User.objects.get(id=user_id)
            if not user.is_admin:
                return jsonify({"error": "Admin access required"}), 403
            return fn(*args, **kwargs)
        except User.DoesNotExist:
            return jsonify({"error": "User not found"}), 404
    return wrapper

@auth_bp.route('/api/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            email:
              type: string
            password:
              type: string
            is_admin:
              type: boolean
              default: false
    responses:
      201:
        description: User created successfully
      400:
        description: Invalid request
    """
    try:
        data = request.get_json()

        if not all(k in data for k in ["username", "email", "password"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            password=generate_password_hash(data['password']),
            is_admin=data.get('is_admin', False)  # Default to false if not provided
        )
        user.save()

        return jsonify({"message": "User created successfully"}), 201

    except NotUniqueError:
        return jsonify({"error": "Username or email already exists"}), 400
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """
    Login user
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    data = request.get_json()

    if not all(k in data for k in ["username", "password"]):
        return jsonify({"error": "Missing required fields"}), 400

    user = User.objects(username=data['username']).first()

    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            "access_token": access_token,
            "is_admin": user.is_admin
        }), 200

    return jsonify({"error": "Invalid credentials"}), 401