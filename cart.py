from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Cart, Order, Product, User, CartItem
from mongoengine.errors import ValidationError, DoesNotExist
from datetime import datetime

cart_bp = Blueprint('cart', __name__)

@cart_bp.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    """
    Get user's cart
    ---
    tags:
      - Cart
    responses:
      200:
        description: Cart details
    """
    user_id = get_jwt_identity()
    try:
        user = User.objects.get(id=user_id)
        cart = Cart.objects(user=user).first()

        if not cart:
            cart = Cart(user=user).save()

        return jsonify({
            'items': [{
                'product_id': str(item.product.id),
                'name': item.product.name,
                'price': item.product.price,
                'quantity': item.quantity
            } for item in cart.items]
        }), 200
    except DoesNotExist:
        return jsonify({"error": "User not found"}), 404

@cart_bp.route('/api/cart/items', methods=['POST'])
@jwt_required()
def add_to_cart():
    """
    Add item to cart
    ---
    tags:
      - Cart
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            product_id:
              type: string
            quantity:
              type: integer
    responses:
      200:
        description: Item added to cart
      400:
        description: Invalid request
      404:
        description: Product not found
    """
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        if not all(k in data for k in ["product_id", "quantity"]):
            return jsonify({"error": "Missing required fields"}), 400

        user = User.objects.get(id=user_id)
        product = Product.objects.get(id=data['product_id'])

        cart = Cart.objects(user=user).first()
        if not cart:
            cart = Cart(user=user)

        # Check if item already exists in cart
        existing_item = None
        for item in cart.items:
            if str(item.product.id) == data['product_id']:
                existing_item = item
                break

        if existing_item:
            existing_item.quantity += data['quantity']
        else:
            cart_item = CartItem(product=product, quantity=data['quantity'])
            cart.items.append(cart_item)

        cart.save()

        return jsonify({
            'items': [{
                'product_id': str(item.product.id),
                'name': item.product.name,
                'price': item.product.price,
                'quantity': item.quantity
            } for item in cart.items]
        }), 200
    except (DoesNotExist, ValidationError) as e:
        return jsonify({"error": str(e)}), 404

@cart_bp.route('/api/cart/items/<product_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(product_id):
    """
    Remove item from cart
    ---
    tags:
      - Cart
    parameters:
      - name: product_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Item removed from cart
      404:
        description: Item not found
    """
    try:
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        cart = Cart.objects(user=user).first()

        if not cart:
            return jsonify({"error": "Cart not found"}), 404

        cart.items = [item for item in cart.items if str(item.product.id) != product_id]
        cart.save()

        return jsonify({
            'items': [{
                'product_id': str(item.product.id),
                'name': item.product.name,
                'price': item.product.price,
                'quantity': item.quantity
            } for item in cart.items]
        }), 200
    except DoesNotExist:
        return jsonify({"error": "User not found"}), 404

@cart_bp.route('/api/orders', methods=['POST'])
@jwt_required()
def create_order():
    """
    Create order from cart
    ---
    tags:
      - Orders
    responses:
      201:
        description: Order created
      400:
        description: Empty cart
    """
    try:
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        cart = Cart.objects(user=user).first()

        if not cart or not cart.items:
            return jsonify({"error": "Cart is empty"}), 400

        total = sum(item.product.price * item.quantity for item in cart.items)

        order = Order(
            user=user,
            items=cart.items,
            total=total,
            status='pending'
        )
        order.save()

        # Clear cart
        cart.items = []
        cart.save()

        return jsonify({
            'id': str(order.id),
            'items': [{
                'product_id': str(item.product.id),
                'name': item.product.name,
                'price': item.product.price,
                'quantity': item.quantity
            } for item in order.items],
            'total': order.total,
            'status': order.status,
            'created_at': order.created_at.isoformat()
        }), 201
    except DoesNotExist:
        return jsonify({"error": "User not found"}), 404

@cart_bp.route('/api/orders', methods=['GET'])
@jwt_required()
def get_orders():
    """
    Get user's orders
    ---
    tags:
      - Orders
    responses:
      200:
        description: List of orders
    """
    try:
        user_id = get_jwt_identity()
        user = User.objects.get(id=user_id)
        orders = Order.objects(user=user)

        return jsonify([{
            'id': str(order.id),
            'items': [{
                'product_id': str(item.product.id),
                'name': item.product.name,
                'price': item.product.price,
                'quantity': item.quantity
            } for item in order.items],
            'total': order.total,
            'status': order.status,
            'created_at': order.created_at.isoformat()
        } for order in orders]), 200
    except DoesNotExist:
        return jsonify({"error": "User not found"}), 404