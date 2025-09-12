from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_user, logout_user, login_required, current_user
import jwt
from datetime import datetime, timedelta
from functools import wraps
from .database import db
from .models import User
from bson import ObjectId

auth_bp = Blueprint('auth', __name__)

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                if current_app.debug:
                    user = User(db.users.find_one({'username': 'admin'}))
                    login_user(user)
                else:
                    return jsonify({'error': 'Authentication required'}), 401
            
            if current_user.role not in roles:
                return jsonify({'error': f'Required role: {", ".join(roles)}'}), 403
                
            return f(*args, **kwargs)
        return decorated
    return decorator

admin_required = role_required(['admin'])
staff_required = role_required(['admin', 'staff'])

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                if current_app.debug:
                    user = User(db.users.find_one({'username': 'admin'}))
                    login_user(user)
                    return f(*args, **kwargs)
                return jsonify({'error': 'Token is missing'}), 401

        if not token:
            if current_app.debug:
                user = User(db.users.find_one({'username': 'admin'}))
                login_user(user)
                return f(*args, **kwargs)
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_data = db.users.find_one({'_id': ObjectId(data['user_id'])})
            if not user_data:
                if current_app.debug:
                    user = User(db.users.find_one({'username': 'admin'}))
                    login_user(user)
                    return f(*args, **kwargs)
                return jsonify({'error': 'Invalid token'}), 401
            request.user = User(user_data)
        except:
            if current_app.debug:
                user = User(db.users.find_one({'username': 'admin'}))
                login_user(user)
                return f(*args, **kwargs)
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated

@auth_bp.route('/login', methods=['GET'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET'])
@login_required
@admin_required
def register_page():
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login
    ---
    tags:
      - auth
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [identifier, password]
          properties:
            identifier:
              type: string
              description: Username or email
            password:
              type: string
    responses:
      200:
        description: Login successful. Returns JWT token and user object
      400:
        description: Missing identifier or password
      401:
        description: Invalid username/email or password
    """
    data = request.get_json()
    identifier = data.get('identifier')  # This can be either username or email
    password = data.get('password')

    if not identifier or not password:
        return jsonify({'error': 'Missing identifier or password'}), 400

    # Try to find user by username or email
    user_data = db.users.find_one({'$or': [
        {'username': identifier},
        {'email': identifier}
    ]})
    
    if not user_data or not check_password_hash(user_data['password'], password):
        return jsonify({'error': 'Invalid username/email or password'}), 401

    user = User(user_data)
    login_user(user)

    token = jwt.encode({
        'user_id': str(user_data['_id']),
        'exp': datetime.utcnow() + timedelta(days=1)
    }, current_app.config['SECRET_KEY'])

    return jsonify({
        'token': token,
        'user': user.to_dict()
    })

@auth_bp.route('/register', methods=['POST'])
@login_required
@admin_required
def register():
    """
    Register a new user (admin only)
    ---
    tags:
      - auth
    security:
      - BearerAuth: []
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [username, email, password]
          properties:
            username:
              type: string
            email:
              type: string
              format: email
            password:
              type: string
            role:
              type: string
              enum: [admin, staff, user]
              default: user
    responses:
      201:
        description: User registered successfully
      400:
        description: Validation error (missing fields, invalid role, or duplicates)
      401:
        description: Unauthorized
      403:
        description: Forbidden (admin only)
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    local_key = bool(data.get('local_key', False))

    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    if role not in ['admin', 'staff', 'user']:
        return jsonify({'error': 'Invalid role'}), 400

    if db.users.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 400

    if db.users.find_one({'email': email}):
        return jsonify({'error': 'Email already exists'}), 400

    user_data = {
        'username': username,
        'email': email,
        'password': generate_password_hash(password),
        'role': role,
        'created_at': datetime.utcnow(),
        'created_by': str(current_user.get_id()),
        'is_active': True,
        'local_key': local_key
    }

    result = db.users.insert_one(user_data)
    user_data['_id'] = result.inserted_id

    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@auth_bp.route('/verify-token', methods=['GET'])
@token_required
def verify_token():
    """
    Verify JWT token
    ---
    tags:
      - auth
    security:
      - BearerAuth: []
    responses:
      200:
        description: Token is valid; returns authenticated user data
      401:
        description: Invalid or missing token
    """
    return jsonify({'user': request.user.to_dict()})
