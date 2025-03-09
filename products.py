from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models import Product
from mongoengine.errors import ValidationError, DoesNotExist
from mongoengine.queryset.visitor import Q
from auth import admin_required

products_bp = Blueprint('products', __name__)

@products_bp.route('/api/products', methods=['GET'])
def get_products():
    """
    Get all products with optional filtering
    ---
    tags:
      - Products
    parameters:
      - name: search
        in: query
        type: string
        description: Search term for product name or description
      - name: min_price
        in: query
        type: number
        description: Minimum price filter
      - name: max_price
        in: query
        type: number
        description: Maximum price filter
      - name: in_stock
        in: query
        type: boolean
        description: Filter for products in stock (stock > 0)
      - name: sort_by
        in: query
        type: string
        enum: [name, price, stock]
        description: Field to sort by
      - name: order
        in: query
        type: string
        enum: [asc, desc]
        description: Sort order (ascending or descending)
    responses:
      200:
        description: List of filtered products
    """
    # Build query filters
    query = Q()

    # Search in name and description
    search_term = request.args.get('search')
    if search_term:
        query = query & (Q(name__icontains=search_term) | Q(description__icontains=search_term))

    # Price range filter
    min_price = request.args.get('min_price', type=float)
    if min_price is not None:
        query = query & Q(price__gte=min_price)

    max_price = request.args.get('max_price', type=float)
    if max_price is not None:
        query = query & Q(price__lte=max_price)

    # Stock availability filter
    in_stock = request.args.get('in_stock', type=bool)
    if in_stock is not None:
        query = query & Q(stock__gt=0) if in_stock else query & Q(stock=0)

    # Get products with filters
    products = Product.objects(query)

    # Apply sorting
    sort_by = request.args.get('sort_by')
    order = request.args.get('order', 'asc')

    if sort_by in ['name', 'price', 'stock']:
        sort_field = f"-{sort_by}" if order == 'desc' else sort_by
        products = products.order_by(sort_field)

    return jsonify([{
        'id': str(p.id),
        'name': p.name,
        'description': p.description,
        'price': p.price,
        'stock': p.stock
    } for p in products]), 200

@products_bp.route('/api/products/<product_id>', methods=['GET'])
def get_product(product_id):
    """
    Get a specific product
    ---
    tags:
      - Products
    parameters:
      - name: product_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Product details
      404:
        description: Product not found
    """
    try:
        product = Product.objects.get(id=product_id)
        return jsonify({
            'id': str(product.id),
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'stock': product.stock
        }), 200
    except DoesNotExist:
        return jsonify({"error": "Product not found"}), 404

@products_bp.route('/api/products', methods=['POST'])
@admin_required
def create_product():
    """
    Create a new product (Admin only)
    ---
    tags:
      - Products
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            price:
              type: number
            stock:
              type: integer
    responses:
      201:
        description: Product created
      400:
        description: Invalid request
      403:
        description: Admin access required
    """
    try:
        data = request.get_json()

        if not all(k in data for k in ["name", "description", "price", "stock"]):
            return jsonify({"error": "Missing required fields"}), 400

        product = Product(**data)
        product.save()

        return jsonify({
            'id': str(product.id),
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'stock': product.stock
        }), 201
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

@products_bp.route('/api/products/<product_id>', methods=['PUT'])
@admin_required
def update_product(product_id):
    """
    Update a product (Admin only)
    ---
    tags:
      - Products
    parameters:
      - name: product_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            price:
              type: number
            stock:
              type: integer
    responses:
      200:
        description: Product updated
      404:
        description: Product not found
      403:
        description: Admin access required
    """
    try:
        product = Product.objects.get(id=product_id)
        data = request.get_json()

        for key, value in data.items():
            setattr(product, key, value)

        product.save()
        return jsonify({
            'id': str(product.id),
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'stock': product.stock
        }), 200
    except DoesNotExist:
        return jsonify({"error": "Product not found"}), 404
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

@products_bp.route('/api/products/<product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    """
    Delete a product (Admin only)
    ---
    tags:
      - Products
    parameters:
      - name: product_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Product deleted
      404:
        description: Product not found
      403:
        description: Admin access required
    """
    try:
        product = Product.objects.get(id=product_id)
        product.delete()
        return jsonify({"message": "Product deleted"}), 200
    except DoesNotExist:
        return jsonify({"error": "Product not found"}), 404