from mongoengine import Document, StringField, FloatField, IntField, ListField, ReferenceField, DateTimeField, EmbeddedDocument, EmbeddedDocumentField, BooleanField, DictField
from datetime import datetime

class DynamicField(Document):
    name = StringField(required=True)
    field_type = StringField(required=True, choices=['string', 'number', 'boolean', 'date'])
    description = StringField()
    entity_type = StringField(required=True, choices=['product', 'cart'])
    required = BooleanField(default=False)
    meta = {'collection': 'dynamic_fields'}

class User(Document):
    username = StringField(required=True, unique=True)
    password = StringField(required=True)  # Will store hashed password
    email = StringField(required=True, unique=True)
    is_admin = BooleanField(default=False)  # New field for admin status
    meta = {'collection': 'users'}

class Product(Document):
    name = StringField(required=True)
    description = StringField(required=True)
    price = FloatField(required=True, min_value=0)
    stock = IntField(required=True, min_value=0)
    custom_fields = DictField(default={})  # Store dynamic fields
    meta = {'collection': 'products'}

class CartItem(EmbeddedDocument):
    product = ReferenceField(Product, required=True)
    quantity = IntField(required=True, min_value=1)
    custom_fields = DictField(default={})  # Store dynamic fields

class Cart(Document):
    user = ReferenceField(User, required=True)
    items = ListField(EmbeddedDocumentField(CartItem), default=list)
    custom_fields = DictField(default={})  # Store dynamic fields
    meta = {'collection': 'carts'}

class Order(Document):
    user = ReferenceField(User, required=True)
    items = ListField(EmbeddedDocumentField(CartItem))
    total = FloatField(required=True, min_value=0)
    status = StringField(required=True, choices=['pending', 'processing', 'completed', 'cancelled'])
    created_at = DateTimeField(default=datetime.utcnow)
    meta = {'collection': 'orders'}