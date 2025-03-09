from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, Product, Order, DynamicField, Cart # Added Cart import
from auth import admin_required
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_session_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.objects(username=username).first()

        if user and user.is_admin and check_password_hash(user.password, password):
            session['admin_logged_in'] = True
            session['admin_username'] = user.username
            flash('Successfully logged in!', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid credentials or not an admin user.', 'danger')

    return render_template('admin/login.html')

@admin_bp.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Successfully logged out.', 'success')
    return redirect(url_for('admin.login'))

@admin_bp.route('/')
@admin_session_required
def dashboard():
    """Admin dashboard with overview statistics"""
    stats = {
        'total_users': User.objects.count(),
        'total_products': Product.objects.count(),
        'total_orders': Order.objects.count(),
        'pending_orders': Order.objects(status='pending').count()
    }
    return render_template('admin/dashboard.html', stats=stats)

@admin_bp.route('/users')
@admin_session_required
def users():
    """User management page"""
    users_list = User.objects.all()
    return render_template('admin/users.html', users=users_list)

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_session_required
def create_user():
    """Create new user"""
    if request.method == 'POST':
        try:
            user = User(
                username=request.form['username'],
                email=request.form['email'],
                password=generate_password_hash(request.form['password']),
                is_admin=request.form.get('is_admin', False) == 'on'
            )
            user.save()
            flash('User created successfully', 'success')
            return redirect(url_for('admin.users'))
        except Exception as e:
            flash(f'Error creating user: {str(e)}', 'danger')
    return render_template('admin/user_form.html')

@admin_bp.route('/products')
@admin_session_required
def products():
    """Product management page"""
    products_list = Product.objects.all()
    return render_template('admin/products.html', products=products_list)

@admin_bp.route('/products/create', methods=['GET', 'POST'])
@admin_session_required
def create_product():
    """Create new product"""
    if request.method == 'POST':
        try:
            # Process custom fields
            custom_fields = {}
            for key, value in request.form.items():
                if key.startswith('custom_fields[') and key.endswith(']'):
                    field_name = key[13:-1]  # Extract field name from custom_fields[name]
                    custom_fields[field_name] = value

            product = Product(
                name=request.form['name'],
                description=request.form['description'],
                price=float(request.form['price']),
                stock=int(request.form['stock']),
                custom_fields=custom_fields
            )
            product.save()
            flash('Product created successfully', 'success')
            return redirect(url_for('admin.products'))
        except Exception as e:
            flash(f'Error creating product: {str(e)}', 'danger')

    # Get dynamic fields for the template
    dynamic_fields = DynamicField.objects(entity_type='product')
    return render_template('admin/product_form.html', dynamic_fields=dynamic_fields)

@admin_bp.route('/orders')
@admin_session_required
def orders():
    """Order management page"""
    orders_list = Order.objects.all().order_by('-created_at')
    return render_template('admin/orders.html', orders=orders_list)

@admin_bp.route('/orders/<order_id>/status', methods=['POST'])
@admin_session_required
def update_order_status(order_id):
    """Update order status"""
    try:
        order = Order.objects.get(id=order_id)
        order.status = request.form['status']
        order.save()
        flash('Order status updated successfully', 'success')
    except Exception as e:
        flash(f'Error updating order status: {str(e)}', 'danger')
    return redirect(url_for('admin.orders'))

@admin_bp.route('/dynamic-fields')
@admin_session_required
def dynamic_fields():
    """Dynamic fields management page"""
    fields = DynamicField.objects.all()
    return render_template('admin/dynamic_fields.html', dynamic_fields=fields)

@admin_bp.route('/dynamic-fields/add', methods=['POST'])
@admin_session_required
def add_dynamic_field():
    """Add new dynamic field"""
    try:
        field = DynamicField(
            name=request.form['name'],
            field_type=request.form['field_type'],
            entity_type=request.form['entity_type'],
            description=request.form.get('description', ''),
            required=request.form.get('required') == 'on'
        )
        field.save()
        flash('Field added successfully', 'success')
    except Exception as e:
        flash(f'Error adding field: {str(e)}', 'danger')
    return redirect(url_for('admin.dynamic_fields'))

@admin_bp.route('/dynamic-fields/<field_id>/delete', methods=['POST'])
@admin_session_required
def delete_dynamic_field(field_id):
    """Delete dynamic field"""
    try:
        field = DynamicField.objects.get(id=field_id)
        # Check if field is in use using proper MongoDB query syntax
        products_using_field = Product.objects(__raw__={'custom_fields.' + field.name: {'$exists': True}}).count()
        carts_using_field = Cart.objects(__raw__={'custom_fields.' + field.name: {'$exists': True}}).count()

        if products_using_field > 0 or carts_using_field > 0:
            flash('Cannot delete field as it is in use', 'danger')
            return redirect(url_for('admin.dynamic_fields'))

        field.delete()
        flash('Field deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting field: {str(e)}', 'danger')
    return redirect(url_for('admin.dynamic_fields'))

@admin_bp.route('/users/<user_id>/delete', methods=['POST'])
@admin_session_required
def delete_user(user_id):
    """Delete user"""
    try:
        # Prevent deleting your own account
        if session.get('admin_username') == User.objects.get(id=user_id).username:
            flash('Cannot delete your own account', 'danger')
            return redirect(url_for('admin.users'))

        user = User.objects.get(id=user_id)
        user.delete()
        flash('User deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    return redirect(url_for('admin.users'))

@admin_bp.route('/products/<product_id>/delete', methods=['POST'])
@admin_session_required
def delete_product(product_id):
    """Delete product"""
    try:
        product = Product.objects.get(id=product_id)
        product.delete()
        flash('Product deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting product: {str(e)}', 'danger')
    return redirect(url_for('admin.products'))