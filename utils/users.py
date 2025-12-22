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


@user_bp.route('/api/<user_id>/graph', methods=['GET'])
@login_required
@staff_required
def get_user_graph(user_id):
    """
    Get graph data for D3.js force-directed visualization.
    Returns nodes (user, devices, credentials) and links.
    """
    try:
        uid = ObjectId(user_id)
    except Exception:
        return jsonify({'error': 'Invalid user_id'}), 400

    user = db.users.find_one({'_id': uid}, {'password': 0})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    nodes = []
    links = []

    # User node
    user_node_id = f"user_{user_id}"
    nodes.append({
        'id': user_node_id,
        'type': 'user',
        'label': user.get('username', 'Unknown'),
        'data': {
            'email': user.get('email'),
            'role': user.get('role'),
            'is_active': user.get('is_active', True),
            'created_at': user.get('created_at').isoformat() if user.get('created_at') else None
        }
    })

    # Devices where user is assigned or owner
    devices = list(db.devices.find({
        '$or': [
            {'assigned_users': uid},
            {'assigned_to': uid},
            {'owner_id': uid}
        ]
    }))

    for device in devices:
        device_id = str(device['_id'])
        device_node_id = f"device_{device_id}"
        
        nodes.append({
            'id': device_node_id,
            'type': 'device',
            'label': device.get('name', 'Unknown'),
            'data': {
                'manufacturer': device.get('manufacturer'),
                'networks': device.get('network_types', []),
                'serial_number': device.get('serial_number')
            }
        })

        # Determine relationship
        is_owner = str(device.get('owner_id')) == user_id
        links.append({
            'source': user_node_id,
            'target': device_node_id,
            'relation': 'owner' if is_owner else 'assigned'
        })

        # Credentials for this device
        credentials = list(db.device_logins.find({'device_id': device['_id']}))
        for cred in credentials:
            cred_id = str(cred['_id'])
            cred_node_id = f"cred_{cred_id}"
            
            nodes.append({
                'id': cred_node_id,
                'type': 'credential',
                'label': cred.get('label') or cred.get('type', 'userpass').upper(),
                'data': {
                    'cred_type': cred.get('type', 'userpass'),
                    'expires_at': cred.get('expires_at').isoformat() if cred.get('expires_at') else None,
                    'is_encrypted': bool(cred.get('encrypted') or cred.get('payload_b64'))
                }
            })
            links.append({
                'source': device_node_id,
                'target': cred_node_id,
                'relation': 'has_credential'
            })

    # Stats
    vault_count = db.vault_items.count_documents({'owner_id': uid})
    
    return jsonify({
        'nodes': nodes,
        'links': links,
        'stats': {
            'devices': len(devices),
            'credentials': sum(1 for n in nodes if n['type'] == 'credential'),
            'vault_items': vault_count
        }
    })


@user_bp.route('/api/<user_id>', methods=['PUT'])
@login_required
@staff_required
def update_user(user_id):
    """Update user data (admin/staff)."""
    try:
        uid = ObjectId(user_id)
    except Exception:
        return jsonify({'error': 'Invalid user_id'}), 400

    if user_id == str(current_user.get_id()):
        return jsonify({'error': 'Cannot modify your own account here'}), 400

    user = db.users.find_one({'_id': uid})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if current_user.role == 'staff' and user.get('role') == 'admin':
        return jsonify({'error': 'Staff cannot modify admin users'}), 403

    data = request.get_json(silent=True) or {}
    updates = {}

    if 'email' in data:
        email = (data['email'] or '').strip()
        if email and email != user.get('email'):
            if db.users.find_one({'email': email, '_id': {'$ne': uid}}):
                return jsonify({'error': 'Email already exists'}), 400
            updates['email'] = email

    if 'username' in data:
        username = (data['username'] or '').strip()
        if username and username != user.get('username'):
            if db.users.find_one({'username': username, '_id': {'$ne': uid}}):
                return jsonify({'error': 'Username already exists'}), 400
            updates['username'] = username

    if 'role' in data and current_user.role == 'admin':
        role = data['role']
        if role in ['admin', 'staff', 'user']:
            updates['role'] = role

    if not updates:
        return jsonify({'error': 'No valid fields to update'}), 400

    updates['updated_at'] = datetime.utcnow()
    updates['updated_by'] = str(current_user.get_id())
    db.users.update_one({'_id': uid}, {'$set': updates})
    
    updated = db.users.find_one({'_id': uid}, {'password': 0})
    updated['_id'] = str(updated['_id'])
    return jsonify({'user': updated})

