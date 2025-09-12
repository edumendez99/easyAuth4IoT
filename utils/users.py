from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from datetime import datetime
from bson import ObjectId
from werkzeug.security import check_password_hash, generate_password_hash
from .database import db
from .auth import admin_required, staff_required
from .models import User

user_bp = Blueprint('user', __name__)

@user_bp.route('/api/list')
@login_required
@admin_required
def get_users_list():
    """
    List all users (admin only)
    ---
    tags:
      - users
    security:
      - BearerAuth: []
    responses:
      200:
        description: List of users without password field
        schema:
          type: array
          items:
            type: object
      401:
        description: Unauthorized
      403:
        description: Forbidden (admin only)
    """
    # Only admins can access the list of all users
    users = list(db.users.find({}, {'password': 0}))
    
    # Convert ObjectIds to strings for JSON serialization
    for user in users:
        user['_id'] = str(user['_id'])
    
    return jsonify(users)

@user_bp.route('/profile')
@login_required
def profile():
    return render_template('users/profile.html')

@user_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """
    Update current user's profile
    ---
    tags:
      - users
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
            current_password:
              type: string
            password:
              type: string
    responses:
      200:
        description: Profile updated successfully
      400:
        description: Validation error
      401:
        description: Unauthorized
    """
    data = request.get_json()
    user_id = str(current_user.get_id())
    
    # Only allow updating certain fields
    allowed_fields = ['email']
    updates = {}
    
    for field in allowed_fields:
        if field in data:
            # Check email uniqueness if email is being updated
            if field == 'email' and data[field] != current_user.email:
                if db.users.find_one({'email': data[field], '_id': {'$ne': ObjectId(user_id)}}):
                    return jsonify({'error': 'Email already exists'}), 400
            updates[field] = data[field]
    
    if 'password' in data:
        if not data.get('current_password'):
            return jsonify({'error': 'Current password is required'}), 400
        
        # Verify current password
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not check_password_hash(user['password'], data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 400
            
        updates['password'] = generate_password_hash(data['password'])
    
    if updates:
        updates['updated_at'] = datetime.utcnow()
        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': updates}
        )
        
    return jsonify({'message': 'Profile updated successfully'})

@user_bp.route('/list')
@login_required
@admin_required
def list_users():
    users = list(db.users.find())
    for user in users:
        user['_id'] = str(user['_id'])
        user.pop('password', None)  # Remove password hash
    return render_template('users/list.html', users=users)

@user_bp.route('/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def user_delete(user_id):
    """
    Delete a user (admin only)
    ---
    tags:
      - users
    parameters:
      - in: path
        name: user_id
        required: true
        type: string
    responses:
      204:
        description: Deleted
      400:
        description: Cannot delete own account
      401:
        description: Unauthorized
      403:
        description: Forbidden (admin only)
      404:
        description: User not found
    """
    # Prevent deleting yourself
    if user_id == str(current_user.get_id()):
        return jsonify({'error': 'Cannot delete your own account'}), 400
        
    result = db.users.delete_one({'_id': ObjectId(user_id)})
    if result.deleted_count == 0:
        return jsonify({'error': 'User not found'}), 404
        
    return '', 204

@user_bp.route('/<user_id>/status', methods=['PUT'])
@login_required
@admin_required
def update_user_status(user_id):
    """
    Update a user's active status (admin only)
    ---
    tags:
      - users
    parameters:
      - in: path
        name: user_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - is_active
          properties:
            is_active:
              type: boolean
    responses:
      200:
        description: Status updated
      400:
        description: Status not specified or cannot modify own status
      401:
        description: Unauthorized
      403:
        description: Forbidden (admin only)
      404:
        description: User not found
    """
    data = request.get_json()
    
    # Prevent modifying your own status
    if user_id == str(current_user.get_id()):
        return jsonify({'error': 'Cannot modify your own status'}), 400
        
    if 'is_active' not in data:
        return jsonify({'error': 'Status not specified'}), 400
        
    result = db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {
            'is_active': data['is_active'],
            'updated_at': datetime.utcnow(),
            'updated_by': str(current_user.get_id())
        }}
    )
    
    if result.modified_count == 0:
        return jsonify({'error': 'User not found'}), 404
        
    return jsonify({'message': 'User status updated successfully'})


@user_bp.route('/<user_id>/local-key', methods=['PUT'])
@login_required
@admin_required
def update_user_local_key(user_id):
    """
    Update a user's local_key flag (admin only)
    ---
    tags:
      - users
    parameters:
      - in: path
        name: user_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - local_key
          properties:
            local_key:
              type: boolean
    responses:
      200:
        description: Flag updated
      400:
        description: local_key not specified or cannot modify own flag
      401:
        description: Unauthorized
      403:
        description: Forbidden (admin only)
      404:
        description: User not found
    """
    data = request.get_json()

    # Prevent modifying your own flag
    if user_id == str(current_user.get_id()):
        return jsonify({'error': 'Cannot modify your own local_key flag'}), 400

    if 'local_key' not in data:
        return jsonify({'error': 'local_key not specified'}), 400

    result = db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {
            'local_key': bool(data['local_key']),
            'updated_at': datetime.utcnow(),
            'updated_by': str(current_user.get_id())
        }}
    )

    if result.modified_count == 0:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'message': 'User local_key updated successfully'})

@user_bp.route('/api/list')
@login_required
@admin_required # Or adjust decorator if non-admins need this list for dropdowns
def api_list_users():
    """
    List users (basic projection)
    ---
    tags:
      - users
    responses:
      200:
        description: List of users with id and username
        schema:
          type: array
          items:
            type: object
            properties:
              _id:
                type: string
              username:
                type: string
      401:
        description: Unauthorized
      403:
        description: Forbidden (admin only)
    """
    users = list(db.users.find({}, {'_id': 1, 'username': 1})) # Project only needed fields
    for user in users:
        user['_id'] = str(user['_id'])
    return jsonify(users)

@user_bp.route('/api/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    """
    Create a new user (admin only)
    ---
    tags:
      - users
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
            email:
              type: string
            password:
              type: string
            role:
              type: string
              enum: [admin, staff, user]
              default: user
    responses:
      201:
        description: User created successfully
      400:
        description: Validation error or duplicate
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

    # Check if username or email already exists
    if db.users.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 400

    if db.users.find_one({'email': email}):
        return jsonify({'error': 'Email already exists'}), 400

    # Create new user
    user_data = {
        'username': username,
        'email': email,
        'password': generate_password_hash(password),
        'role': role,
        'created_at': datetime.utcnow(),
        'created_by': str(current_user.get_id()),
        'updated_at': datetime.utcnow(),
        'updated_by': str(current_user.get_id()),
        'is_active': True,
        'local_key': local_key
    }

    result = db.users.insert_one(user_data)
    user_data['_id'] = str(result.inserted_id)
    
    # Remove password before returning
    user_data.pop('password', None)
    
    return jsonify({
        'message': 'User created successfully',
        'user': user_data
    }), 201


@user_bp.route('/api/search')
@login_required
@staff_required
def api_search_users():
    """
    Search users by username (staff and admin).
    Returns a limited projection suitable for assignment UIs.
    Query params:
      - q: substring (case-insensitive)
      - limit: optional int (default 200, max 500)
    """
    q = (request.args.get('q') or '').strip()
    try:
        limit = int(request.args.get('limit') or 200)
    except Exception:
        limit = 200
    limit = max(1, min(limit, 500))

    flt = {}
    if q:
        flt['username'] = {'$regex': q, '$options': 'i'}

    users = list(db.users.find(flt, {'_id': 1, 'username': 1, 'role': 1}).sort('username', 1).limit(limit))
    for u in users:
        u['_id'] = str(u['_id'])
    return jsonify({'users': users})


@user_bp.route('/api/by-ids', methods=['POST'])
@login_required
@staff_required
def api_users_by_ids():
    """
    Return minimal info for a list of user IDs.
    Body: { ids: ["..."] }
    """
    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    if not isinstance(ids, list):
        return jsonify({'users': []})
    oids = []
    for s in ids:
        try:
            oids.append(ObjectId(str(s)))
        except Exception:
            continue
    if not oids:
        return jsonify({'users': []})
    users = list(db.users.find({'_id': {'$in': oids}}, {'_id': 1, 'username': 1, 'role': 1}))
    for u in users:
        u['_id'] = str(u['_id'])
    return jsonify({'users': users})
