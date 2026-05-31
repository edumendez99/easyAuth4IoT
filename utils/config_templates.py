import io
from flask import Blueprint, request, jsonify, render_template, send_file
from flask_login import login_required, current_user
from bson import ObjectId
from datetime import datetime
import re
import json
import xml.etree.ElementTree as ET
from .database import db, fs
from .auth import staff_required


config_templates_bp = Blueprint('config_templates', __name__)


def _obj_id(id_str: str):
    try:
        return ObjectId(id_str)
    except Exception:
        return None


def _serialize_template(doc: dict) -> dict:
    if not doc:
        return None
    d = doc.copy()
    d['_id'] = str(d['_id'])
    if 'owner_id' in d and d['owner_id']:
        d['owner_id'] = str(d['owner_id'])
    return d


def _can_view_template(user, template: dict) -> bool:
    """Admin can view all, staff can view own templates."""
    if not template:
        return False
    if user.role == 'admin':
        return True
    if user.role == 'staff':
        owner_id = str(template.get('owner_id') or '')
        return owner_id == str(user.get_id())
    return False


def _can_edit_template(user, template: dict) -> bool:
    """Admin can edit all, staff can edit own templates."""
    return _can_view_template(user, template)


# ─────────────────────────────────────────────────────────────────────────────
# Format validation
# ─────────────────────────────────────────────────────────────────────────────

def _validate_content_format(content: str, file_type: str) -> tuple:
    """
    Validate content format based on file type.
    Returns (is_valid: bool, error_message: str or None)
    """
    if not content:
        return (True, None)
    
    # Replace placeholders with sample values for validation
    sample_content = re.sub(r'\{\{\s*device\.custom\.\w+\s*\}\}', 'sample_value', content)
    sample_content = re.sub(r'\{\{\s*device\.\w+\s*\}\}', 'sample_value', sample_content)
    sample_content = re.sub(r'\{\{\s*credential\.\w+\s*\}\}', 'sample_value', sample_content)
    
    if file_type == 'json':
        try:
            json.loads(sample_content)
            return (True, None)
        except json.JSONDecodeError as e:
            return (False, f'JSON inválido: {str(e)}')
    
    elif file_type == 'xml':
        try:
            ET.fromstring(sample_content)
            return (True, None)
        except ET.ParseError as e:
            return (False, f'XML inválido: {str(e)}')
    
    elif file_type == 'yaml':
        try:
            import yaml as _yaml
            _yaml.safe_load(sample_content)
            return (True, None)
        except Exception as e:
            return (False, f'YAML inválido: {str(e)}')
    
    # ini, conf, env, sh, txt - no strict validation
    return (True, None)


# ─────────────────────────────────────────────────────────────────────────────
# Template rendering engine
# ─────────────────────────────────────────────────────────────────────────────

def _get_device_context(device_id: str) -> dict:
    """Build context dict from a device document."""
    did = _obj_id(device_id)
    if not did:
        return {}
    device = db.devices.find_one({'_id': did})
    if not device:
        return {}
    ctx = {
        '_id': str(device['_id']),
        'name': device.get('name') or '',
        'manufacturer': device.get('manufacturer') or '',
        'country_of_manufacture': device.get('country_of_manufacture') or '',
        'barcode': device.get('barcode') or '',
        'serial_number': device.get('serial_number') or '',
        'description': device.get('description') or '',
        'network_types': device.get('network_types') or [],
        'custom': device.get('custom_fields') or {},
    }
    return ctx


def _get_credential_context(device_id: str, credential_id: str = None) -> dict:
    """Build context dict from device credentials.
    
    If credential_id is provided, returns that specific credential.
    Otherwise returns the first credential found.
    """
    from .crypto_server import decrypt_json
    
    did = _obj_id(device_id)
    if not did:
        return {}
    
    query = {'device_id': did}
    if credential_id:
        cid = _obj_id(credential_id)
        if cid:
            query['_id'] = cid
    
    cred = db.device_logins.find_one(query)
    if not cred:
        return {}
    
    ctx = {
        '_id': str(cred['_id']),
        'type': cred.get('type') or 'userpass',
    }
    
    # Try to decrypt server-encrypted credentials
    if cred.get('payload_b64') and isinstance(cred.get('meta'), dict) and cred['meta'].get('server'):
        try:
            payload = decrypt_json(cred['payload_b64'], cred['meta'])
            ctx.update(payload)
        except Exception:
            pass
    else:
        # Plaintext fields (legacy)
        if cred.get('username'):
            ctx['username'] = cred['username']
        if cred.get('password'):
            ctx['password'] = cred['password']
        if cred.get('token'):
            ctx['token'] = cred['token']
        if cred.get('label'):
            ctx['label'] = cred['label']
        if cred.get('note'):
            ctx['note'] = cred['note']
    
    return ctx


def render_template_content(content: str, device_id: str = None, credential_id: str = None) -> str:
    """
    Render a config template by replacing placeholders.
    
    Supported placeholders:
      - {{ device.* }} - Device fields (name, serial_number, barcode, etc.)
      - {{ device.custom.* }} - Custom device fields
      - {{ credential.* }} - Credential fields (username, password, token, etc.)
    
    Returns the rendered content string.
    """
    if not content:
        return ''
    
    device_ctx = _get_device_context(device_id) if device_id else {}
    cred_ctx = _get_credential_context(device_id, credential_id) if device_id else {}
    
    # Pattern: {{ namespace.field }} or {{ device.custom.field }} with optional whitespace
    pattern = r'\{\{\s*(device\.custom|device|credential)\.(\w+)\s*\}\}'
    
    def replacer(match):
        namespace = match.group(1)
        field = match.group(2)
        if namespace == 'device.custom':
            custom = device_ctx.get('custom', {})
            value = custom.get(field, '')
        elif namespace == 'device':
            value = device_ctx.get(field, '')
        elif namespace == 'credential':
            value = cred_ctx.get(field, '')
        else:
            value = ''
        # Handle lists (e.g., network_types)
        if isinstance(value, list):
            value = ','.join(str(v) for v in value)
        elif isinstance(value, dict):
            value = json.dumps(value)
        return str(value) if value is not None else ''
    
    return re.sub(pattern, replacer, content)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@config_templates_bp.route('/list', methods=['GET'])
@login_required
@staff_required
def list_page():
    """Render the Config Templates management page."""
    return render_template('config_templates/list.html')


@config_templates_bp.route('/api', methods=['GET'])
@login_required
@staff_required
def list_templates():
    """
    List config templates visible to the current user.
    Admin sees all, staff sees own.
    """
    uid = str(current_user.get_id())
    
    if current_user.role == 'admin':
        query = {}
    else:
        query = {'owner_id': _obj_id(uid)}
    
    # Optional search
    q = (request.args.get('q') or '').strip()
    if q:
        rx = {'$regex': q, '$options': 'i'}
        query = {'$and': [query, {'$or': [
            {'name': rx},
            {'description': rx},
            {'file_type': rx},
        ]}]} if query else {'$or': [{'name': rx}, {'description': rx}, {'file_type': rx}]}
    
    docs = list(db.config_templates.find(query).sort('name', 1))
    
    # Enrich with owner username
    owner_ids = {d.get('owner_id') for d in docs if d.get('owner_id')}
    owner_map = {}
    if owner_ids:
        for u in db.users.find({'_id': {'$in': list(owner_ids)}}, {'_id': 1, 'username': 1}):
            owner_map[u['_id']] = u.get('username')
    
    templates = []
    for d in docs:
        t = _serialize_template(d)
        if d.get('owner_id') in owner_map:
            t['owner_username'] = owner_map[d['owner_id']]
        templates.append(t)
    
    # Also fetch generic file entries (same access rules)
    file_query = {} if current_user.role == 'admin' else {'owner_id': _obj_id(uid)}
    if q:
        rx_f = {'$regex': q, '$options': 'i'}
        name_filter = {'$or': [{'name': rx_f}, {'filename': rx_f}]}
        file_query = {'$and': [file_query, name_filter]} if file_query else name_filter

    file_docs = list(db.config_template_files.find(file_query).sort('uploaded_at', -1))

    # Enrich file entries with owner usernames (reuse owner_map, fetch missing)
    missing_ids = {d['owner_id'] for d in file_docs if d.get('owner_id') and d['owner_id'] not in owner_map}
    if missing_ids:
        for u in db.users.find({'_id': {'$in': list(missing_ids)}}, {'_id': 1, 'username': 1}):
            owner_map[u['_id']] = u.get('username')

    files = []
    for d in file_docs:
        files.append({
            '_id': str(d['_id']),
            'kind': 'file',
            'name': d.get('name') or d.get('filename', ''),
            'label': d.get('label') or '',
            'filename': d.get('filename', ''),
            'size': d.get('size', 0),
            'content_type': d.get('content_type', 'application/octet-stream'),
            'owner_id': str(d['owner_id']) if d.get('owner_id') else '',
            'owner_username': owner_map.get(d.get('owner_id'), ''),
            'uploaded_at': d.get('uploaded_at').isoformat() if d.get('uploaded_at') else None,
        })

    return jsonify({'templates': templates, 'files': files})


@config_templates_bp.route('/api', methods=['POST'])
@login_required
@staff_required
def create_template():
    """
    Create a new config template.
    
    Body JSON:
      - name: string (required)
      - content: string (required) - The template content with placeholders
      - file_type: string (optional) - e.g., 'conf', 'ini', 'json', 'yaml'
      - description: string (optional)
    """
    data = request.get_json(silent=True) or {}
    
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    
    content = data.get('content') or ''
    if not content:
        return jsonify({'error': 'content is required'}), 400
    
    file_type = (data.get('file_type') or '').strip() or 'txt'
    description = (data.get('description') or '').strip() or None
    
    # Validate content format
    is_valid, error_msg = _validate_content_format(content, file_type)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    now = datetime.utcnow()
    doc = {
        'name': name,
        'content': content,
        'file_type': file_type,
        'description': description,
        'owner_id': _obj_id(str(current_user.get_id())),
        'created_at': now,
        'created_by': str(current_user.get_id()),
        'updated_at': now,
        'updated_by': str(current_user.get_id()),
    }
    
    ins = db.config_templates.insert_one(doc)
    template = db.config_templates.find_one({'_id': ins.inserted_id})
    return jsonify({'template': _serialize_template(template)}), 201


@config_templates_bp.route('/api/<template_id>', methods=['GET'])
@login_required
@staff_required
def get_template(template_id):
    """Get a single config template by ID."""
    tid = _obj_id(template_id)
    if not tid:
        return jsonify({'error': 'Invalid template_id'}), 400
    
    template = db.config_templates.find_one({'_id': tid})
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    if not _can_view_template(current_user, template):
        return jsonify({'error': 'Forbidden'}), 403
    
    # Enrich with owner username
    if template.get('owner_id'):
        u = db.users.find_one({'_id': template['owner_id']}, {'username': 1})
        if u:
            template['owner_username'] = u.get('username')
    
    return jsonify(_serialize_template(template))


@config_templates_bp.route('/api/<template_id>', methods=['PUT'])
@login_required
@staff_required
def update_template(template_id):
    """Update an existing config template."""
    tid = _obj_id(template_id)
    if not tid:
        return jsonify({'error': 'Invalid template_id'}), 400
    
    template = db.config_templates.find_one({'_id': tid})
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    if not _can_edit_template(current_user, template):
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.get_json(silent=True) or {}
    update = {}
    
    if 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'name cannot be empty'}), 400
        update['name'] = name
    
    if 'content' in data:
        update['content'] = data.get('content') or ''
    
    if 'file_type' in data:
        update['file_type'] = (data.get('file_type') or '').strip() or 'txt'
    
    if 'description' in data:
        update['description'] = (data.get('description') or '').strip() or None
    
    if not update:
        return jsonify({'error': 'No valid fields to update'}), 400
    
    # Validate content format if content or file_type changed
    content_to_validate = update.get('content', template.get('content', ''))
    file_type_to_validate = update.get('file_type', template.get('file_type', 'txt'))
    is_valid, error_msg = _validate_content_format(content_to_validate, file_type_to_validate)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    update['updated_at'] = datetime.utcnow()
    update['updated_by'] = str(current_user.get_id())
    
    db.config_templates.update_one({'_id': tid}, {'$set': update})
    template = db.config_templates.find_one({'_id': tid})
    
    if template.get('owner_id'):
        u = db.users.find_one({'_id': template['owner_id']}, {'username': 1})
        if u:
            template['owner_username'] = u.get('username')
    
    return jsonify({'template': _serialize_template(template)})


@config_templates_bp.route('/api/<template_id>', methods=['DELETE'])
@login_required
@staff_required
def delete_template(template_id):
    """Delete a config template."""
    tid = _obj_id(template_id)
    if not tid:
        return jsonify({'error': 'Invalid template_id'}), 400
    
    template = db.config_templates.find_one({'_id': tid})
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    if not _can_edit_template(current_user, template):
        return jsonify({'error': 'Forbidden'}), 403
    
    db.config_templates.delete_one({'_id': tid})
    return '', 204


@config_templates_bp.route('/api/<template_id>/render', methods=['POST'])
@login_required
@staff_required
def render_template_api(template_id):
    """
    Render a config template with device/credential data.
    
    Body JSON:
      - device_id: string (required) - The device to use for placeholders
      - credential_id: string (optional) - Specific credential to use
    
    Returns:
      - rendered: string - The rendered config content
      - filename: string - Suggested filename
    """
    tid = _obj_id(template_id)
    if not tid:
        return jsonify({'error': 'Invalid template_id'}), 400
    
    template = db.config_templates.find_one({'_id': tid})
    if not template:
        return jsonify({'error': 'Template not found'}), 404
    
    if not _can_view_template(current_user, template):
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.get_json(silent=True) or {}
    device_id = (data.get('device_id') or '').strip()
    credential_id = (data.get('credential_id') or '').strip() or None
    
    if not device_id:
        return jsonify({'error': 'device_id is required'}), 400
    
    # Verify device exists and user can access it
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    # Check device access (admin sees all, staff sees owned, user sees assigned)
    uid = str(current_user.get_id())
    can_access = False
    if current_user.role == 'admin':
        can_access = True
    elif current_user.role == 'staff':
        can_access = str(device.get('owner_id') or '') == uid
    else:
        assigned = device.get('assigned_users') or []
        can_access = any(str(x) == uid for x in assigned)
    
    if not can_access:
        return jsonify({'error': 'Cannot access this device'}), 403
    
    # Render the template
    content = template.get('content') or ''
    rendered = render_template_content(content, device_id, credential_id)
    
    # Generate suggested filename
    device_name = (device.get('name') or 'device').replace(' ', '_')
    serial = device.get('serial_number') or ''
    file_type = template.get('file_type') or 'txt'
    template_name = (template.get('name') or 'config').replace(' ', '_')
    
    if serial:
        filename = f"{template_name}_{device_name}_{serial}.{file_type}"
    else:
        filename = f"{template_name}_{device_name}.{file_type}"
    
    return jsonify({
        'rendered': rendered,
        'filename': filename,
        'device_name': device.get('name'),
        'template_name': template.get('name'),
    })


@config_templates_bp.route('/api/preview', methods=['POST'])
@login_required
@staff_required
def preview_template():
    """
    Preview a template with sample data (without saving).
    Useful for testing templates before creating them.
    
    Body JSON:
      - content: string (required) - Template content to preview
      - device_id: string (optional) - Device to use for real data
      - credential_id: string (optional) - Credential to use
    """
    data = request.get_json(silent=True) or {}
    content = data.get('content') or ''
    device_id = (data.get('device_id') or '').strip() or None
    credential_id = (data.get('credential_id') or '').strip() or None
    
    if device_id:
        rendered = render_template_content(content, device_id, credential_id)
    else:
        # Use sample data for preview
        sample_device = {
            'name': 'SampleDevice',
            'serial_number': 'SN123456',
            'barcode': 'BC789012',
            'manufacturer': 'Acme Corp',
            'country_of_manufacture': 'USA',
            'description': 'Sample device for preview',
            'network_types': ['WiFi', 'Bluetooth'],
        }
        sample_cred = {
            'username': 'device_user',
            'password': 'secret123',
            'token': 'tok_abc123xyz',
            'label': 'Main credential',
        }
        
        # Replace placeholders with sample data
        pattern = r'\{\{\s*(device|credential)\.(\w+)\s*\}\}'
        
        def replacer(match):
            namespace = match.group(1)
            field = match.group(2)
            if namespace == 'device':
                value = sample_device.get(field, f'[device.{field}]')
            elif namespace == 'credential':
                value = sample_cred.get(field, f'[credential.{field}]')
            else:
                value = ''
            if isinstance(value, list):
                value = ','.join(str(v) for v in value)
            return str(value) if value is not None else ''
        
        rendered = re.sub(pattern, replacer, content)

    return jsonify({'rendered': rendered})


# ─────────────────────────────────────────────────────────────────────────────
# Generic config file attachments
# ─────────────────────────────────────────────────────────────────────────────

@config_templates_bp.route('/api/files', methods=['POST'])
@login_required
@staff_required
def upload_config_file():
    f = request.files.get('file')
    if not f or f.filename == '':
        return jsonify({'error': 'File is required'}), 400

    name = (request.form.get('name') or '').strip() or f.filename
    label = (request.form.get('label') or '').strip() or None
    data = f.read()
    content_type = f.content_type or 'application/octet-stream'
    filename = f.filename

    gfs_id = fs.put(data, filename=filename, content_type=content_type,
                    metadata={'type': 'config_template_file', 'owner': str(current_user.get_id())})

    now = datetime.utcnow()
    doc = {
        'name': name,
        'label': label,
        'filename': filename,
        'gfs_id': gfs_id,
        'size': len(data),
        'content_type': content_type,
        'owner_id': _obj_id(str(current_user.get_id())),
        'uploaded_by': str(current_user.get_id()),
        'uploaded_at': now,
    }
    inserted = db.config_template_files.insert_one(doc)
    return jsonify({'_id': str(inserted.inserted_id), 'name': name, 'filename': filename}), 201


@config_templates_bp.route('/api/files/<file_id>', methods=['GET'])
@login_required
@staff_required
def download_config_file(file_id):
    fid = _obj_id(file_id)
    if not fid:
        return jsonify({'error': 'Invalid file_id'}), 400

    meta = db.config_template_files.find_one({'_id': fid})
    if not meta:
        return jsonify({'error': 'File not found'}), 404

    uid = str(current_user.get_id())
    if current_user.role != 'admin' and str(meta.get('owner_id')) != uid:
        return jsonify({'error': 'Forbidden'}), 403

    try:
        gridout = fs.get(meta['gfs_id'])
    except Exception:
        return jsonify({'error': 'File data not found'}), 404

    return send_file(
        io.BytesIO(gridout.read()),
        mimetype=meta.get('content_type') or 'application/octet-stream',
        as_attachment=True,
        download_name=meta.get('filename') or 'download',
    )


@config_templates_bp.route('/api/files/<file_id>', methods=['DELETE'])
@login_required
@staff_required
def delete_config_file(file_id):
    fid = _obj_id(file_id)
    if not fid:
        return jsonify({'error': 'Invalid file_id'}), 400

    meta = db.config_template_files.find_one({'_id': fid})
    if not meta:
        return jsonify({'error': 'File not found'}), 404

    uid = str(current_user.get_id())
    if current_user.role != 'admin' and str(meta.get('owner_id')) != uid:
        return jsonify({'error': 'Forbidden'}), 403

    try:
        fs.delete(meta['gfs_id'])
    except Exception:
        pass
    db.config_template_files.delete_one({'_id': fid})
    return jsonify({'ok': True})
