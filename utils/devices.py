from flask import Blueprint, request, jsonify, current_app, render_template, send_file, url_for
from flask_login import login_required, current_user
from bson import ObjectId
from datetime import datetime
from .database import db, fs
from .auth import staff_required, admin_required
import io
import json
from .crypto_server import encrypt_json, decrypt_json, encrypt_bytes, decrypt_bytes, hmac_tag


devices_bp = Blueprint('devices', __name__)

ALLOWED_NETWORKS = {"WiFi", "LoRaWAN", "Bluetooth", "3G/4G", "NB-IoT", "LTE-M"}
# Max bytes to store inline (not using inline now for simplicity). Files are stored in GridFS.
CRED_INLINE_MAX_BYTES = 256 * 1024


def _obj_id(id_str: str):
    try:
        return ObjectId(id_str)
    except Exception:
        return None


def _is_owner(user, device: dict) -> bool:
    if not device:
        return False
    owner_id = str(device.get('owner_id') or '')
    return user.role in ['admin', 'staff'] and owner_id == str(user.get_id())


def _is_assigned(user, device: dict) -> bool:
    if not device:
        return False
    uid = str(user.get_id())
    assigned = device.get('assigned_users') or []
    # Backward compat: assigned_to single
    if not assigned and device.get('assigned_to'):
        assigned = [device.get('assigned_to')]
    return any(str(x) == uid for x in assigned)


def _can_view_device(user, device: dict) -> bool:
    if not device:
        return False
    # Admin can view all
    if user.role == 'admin':
        return True
    # Staff owner can view
    if _is_owner(user, device):
        return True
    # Assigned users can view
    if _is_assigned(user, device):
        return True
    return False


def _can_edit_device(user, device: dict) -> bool:
    if not device:
        return False
    # Admin can edit all
    if user.role == 'admin':
        return True
    # Only staff owner can edit
    return _is_owner(user, device)


def _can_view_credentials(user, device: dict) -> bool:
    """Allow admin, staff owner, and assigned users to view credentials."""
    if not device:
        return False
    if user.role == 'admin':
        return True
    if _is_owner(user, device):
        return True
    return _is_assigned(user, device)


def _serialize_device(device: dict) -> dict:
    if not device:
        return None
    d = device.copy()
    d['_id'] = str(d['_id'])
    if 'owner_id' in d and d['owner_id']:
        d['owner_id'] = str(d['owner_id'])
    # Normalize to list
    assigned = d.get('assigned_users') or []
    if isinstance(assigned, list):
        d['assigned_users'] = [str(x) for x in assigned]
    else:
        # Backward compatibility: single assigned_to field
        single = d.get('assigned_to')
        d['assigned_users'] = [str(single)] if single else []
    return d


@devices_bp.route('/list', methods=['GET'])
@login_required
def list_page():
    return render_template('devices/list.html')


@devices_bp.route('/api', methods=['GET'])
@login_required
def list_devices_api():
    uid = str(current_user.get_id())
    # Role-scoped base filter
    if current_user.role == 'admin':
        role_q = {}
    elif current_user.role == 'staff':
        role_q = {'owner_id': _obj_id(uid)}
    else:
        role_q = {'$or': [
            {'assigned_users': _obj_id(uid)},
            {'assigned_to': _obj_id(uid)}  # backward compat
        ]}

    # Optional text search across several fields and owner username
    q = (request.args.get('q') or '').strip()
    final_q = role_q
    if q:
        rx = {'$regex': q, '$options': 'i'}
        # Username match -> map to user IDs (used for owner and assigned users)
        user_ids = [u['_id'] for u in db.users.find({'username': rx}, {'_id': 1})]
        or_parts = [
            {'name': rx},
            {'manufacturer': rx},
            {'country_of_manufacture': rx},
            {'barcode': rx},
            {'serial_number': rx},
            {'description': rx},
            {'network_types': rx},
        ]
        if user_ids:
            or_parts.append({'owner_id': {'$in': user_ids}})
            or_parts.append({'assigned_users': {'$in': user_ids}})
            or_parts.append({'assigned_to': {'$in': user_ids}})
        final_q = {'$and': [role_q, {'$or': or_parts}]} if role_q else {'$or': or_parts}

    # Fetch devices
    docs = list(db.devices.find(final_q))

    # Enrich with owner_username in batch
    owner_oids = {d.get('owner_id') for d in docs if d.get('owner_id')}
    owner_map = {}
    if owner_oids:
        for u in db.users.find({'_id': {'$in': list(owner_oids)}}, {'_id': 1, 'username': 1}):
            owner_map[u['_id']] = u.get('username')
    for d in docs:
        if d.get('owner_id') in owner_map:
            d['owner_username'] = owner_map[d['owner_id']]

    devices = [_serialize_device(d) for d in docs]
    return jsonify({'devices': devices})


@devices_bp.route('/api/suggest', methods=['GET'])
@login_required
def suggest_devices():
    """
    Devuelve sugerencias de autocompletado para la barra de búsqueda de dispositivos.
    Retorna valores de distintos campos (nombre, fabricante, país, barcode, serie, descripción, redes),
    usernames de owner y de asignados, todo filtrado por el alcance del rol del usuario y por el texto q.
    """
    uid = str(current_user.get_id())
    # Role-scoped base filter
    if current_user.role == 'admin':
        role_q = {}
    elif current_user.role == 'staff':
        role_q = {'owner_id': _obj_id(uid)}
    else:
        role_q = {'$or': [
            {'assigned_users': _obj_id(uid)},
            {'assigned_to': _obj_id(uid)}  # backward compat
        ]}

    q = (request.args.get('q') or '').strip()
    limit = int(request.args.get('limit', 12))
    rx = {'$regex': q, '$options': 'i'} if q else None

    suggestions = []
    seen = set()  # (type, value)

    def add_sug(s_type: str, value: str, label: str = None):
        if not value:
            return
        key = (s_type, value)
        if key in seen:
            return
        seen.add(key)
        suggestions.append({'type': s_type, 'value': value, 'label': label or value})

    # Helper to distinct values for a field with optional regex
    def field_suggestions(field: str, pretty: str, per_field_limit: int = 6):
        filt = role_q.copy() if role_q else {}
        if rx:
            filt[field] = rx
        try:
            vals = db.devices.distinct(field, filt)
        except Exception:
            vals = []
        # Keep order by frequency relevance: approximate by limiting after query
        count = 0
        for v in vals:
            if not v:
                continue
            if rx and not isinstance(v, str):
                # Ensure we only try to regex strings. Non-strings are included only when q empty
                pass
            label = f"{pretty}: {v}"
            add_sug(field, str(v), label)
            count += 1
            if count >= per_field_limit:
                break

    # Device fields
    field_suggestions('name', 'Nombre', 6)
    field_suggestions('manufacturer', 'Fabricante', 5)
    field_suggestions('country_of_manufacture', 'País', 5)
    field_suggestions('barcode', 'Código de barras', 4)
    field_suggestions('serial_number', 'Número de serie', 4)
    field_suggestions('description', 'Descripción', 3)

    # Networks (prefer present in DB)
    try:
        present_nets = set(db.devices.distinct('network_types', role_q))
    except Exception:
        present_nets = set()
    net_candidates = [n for n in ALLOWED_NETWORKS if (not q or (rx and isinstance(n, str) and __import__('re').search(q, n, __import__('re').I)))]
    # Intersect with present nets first, then others
    ordered = [n for n in net_candidates if n in present_nets] + [n for n in net_candidates if n not in present_nets]
    for n in ordered:
        add_sug('network_types', n, f"Red: {n}")

    # Owner usernames (only those who own devices in scope)
    try:
        owner_ids = [oid for oid in db.devices.distinct('owner_id', role_q) if oid]
    except Exception:
        owner_ids = []
    if owner_ids:
        ufilter = {'_id': {'$in': owner_ids}}
        if rx:
            ufilter['username'] = rx
        for u in db.users.find(ufilter, {'username': 1}).limit(20):
            username = u.get('username')
            add_sug('owner', username, f"Owner: {username}")

    # Assigned usernames (unwind assigned_users)
    try:
        assigned_ids = [oid for oid in db.devices.distinct('assigned_users', role_q) if oid]
    except Exception:
        assigned_ids = []
    if assigned_ids:
        ufilter = {'_id': {'$in': assigned_ids}}
        if rx:
            ufilter['username'] = rx
        for u in db.users.find(ufilter, {'username': 1}).limit(20):
            username = u.get('username')
            add_sug('assigned', username, f"Asignado: {username}")

    # Trim to overall limit maintaining order
    if len(suggestions) > limit:
        suggestions = suggestions[:limit]

    return jsonify({'suggestions': suggestions})


@devices_bp.route('/api', methods=['POST'])
@login_required
@staff_required
def create_device():
    """
    Crea un dispositivo. El propietario siempre es un usuario 'staff'.
    - Si el usuario autenticado es 'staff', será el owner.
    - Si es 'admin', debe especificar el owner por owner_user_id o owner_username (staff existente).
    Acepta campos opcionales: manufacturer, network_types, country_of_manufacture, barcode, serial_number, description.
    Permite establecer asignaciones iniciales por usernames con assigned_usernames.
    """
    data = request.get_json(silent=True) or {}

    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    # Determinar owner
    owner_oid = None
    if current_user.role == 'staff':
        owner_oid = _obj_id(str(current_user.get_id()))
    else:  # admin
        owner_id_str = (data.get('owner_user_id') or '').strip()
        owner_username = (data.get('owner_username') or '').strip()
        if owner_id_str:
            owner_oid = _obj_id(owner_id_str)
            if not owner_oid:
                return jsonify({'error': 'Invalid owner_user_id'}), 400
            owner_user = db.users.find_one({'_id': owner_oid})
        elif owner_username:
            owner_user = db.users.find_one({'username': owner_username})
            if not owner_user:
                return jsonify({'error': 'Owner username not found'}), 404
            if owner_user.get('role') != 'staff':
                return jsonify({'error': 'Owner must be a staff user'}), 400
            owner_oid = owner_user['_id']
        else:
            return jsonify({'error': 'owner_user_id or owner_username is required for admin'}), 400
        if not owner_user:
            return jsonify({'error': 'Owner user not found'}), 404
        if owner_user.get('role') != 'staff':
            return jsonify({'error': 'Owner must be a staff user'}), 400

    # Campos opcionales
    manufacturer = (data.get('manufacturer') or '').strip() or None
    country = (data.get('country_of_manufacture') or '').strip() or None
    barcode = (data.get('barcode') or '').strip() or None
    serial_number = (data.get('serial_number') or '').strip() or None
    description = (data.get('description') or '').strip() or None

    # Redes
    networks = data.get('network_types')
    if networks is None:
        network_types = []
    elif isinstance(networks, list):
        cleaned = []
        seen = set()
        for n in networks:
            s = str(n).strip()
            if not s:
                continue
            if s not in ALLOWED_NETWORKS:
                return jsonify({'error': f'Invalid network type: {s}'}), 400
            if s not in seen:
                seen.add(s)
                cleaned.append(s)
        network_types = cleaned
    else:
        return jsonify({'error': 'network_types must be an array'}), 400

    # Asignaciones iniciales por username (opcional)
    assigned_usernames = data.get('assigned_usernames')
    assigned_oids = []
    if isinstance(assigned_usernames, list):
        names = [str(u).strip() for u in assigned_usernames if str(u).strip()]
        if names:
            users = list(db.users.find({'username': {'$in': names}}, {'_id': 1, 'username': 1}))
            found_names = {u['username'] for u in users}
            missing = [n for n in names if n not in found_names]
            if missing:
                return jsonify({'error': f"Usernames not found: {', '.join(missing)}"}), 400
            by_name = {u['username']: u['_id'] for u in users}
            seen = set()
            for n in names:
                if n in seen:
                    continue
                seen.add(n)
                assigned_oids.append(by_name[n])
    elif assigned_usernames is not None:
        return jsonify({'error': 'assigned_usernames must be an array if provided'}), 400

    # Custom fields (key-value pairs for templates)
    custom_fields = data.get('custom_fields')
    if custom_fields is not None and not isinstance(custom_fields, dict):
        return jsonify({'error': 'custom_fields must be an object'}), 400
    if custom_fields:
        # Sanitize keys: only alphanumeric and underscore
        custom_fields = {k.replace(' ', '_'): v for k, v in custom_fields.items() if k}

    now = datetime.utcnow()
    doc = {
        'name': name,
        'owner_id': owner_oid,
        'assigned_users': assigned_oids,
        'manufacturer': manufacturer,
        'network_types': network_types,
        'country_of_manufacture': country,
        'barcode': barcode,
        'serial_number': serial_number,
        'description': description,
        'custom_fields': custom_fields or {},
        'created_at': now,
        'created_by': str(current_user.get_id()),
        'updated_at': now,
        'updated_by': str(current_user.get_id()),
    }
    # Compat: assigned_to cuando hay solo uno
    doc['assigned_to'] = assigned_oids[0] if len(assigned_oids) == 1 else None

    ins = db.devices.insert_one(doc)
    device = db.devices.find_one({'_id': ins.inserted_id})
    return jsonify({'device': _serialize_device(device)}), 201


@devices_bp.route('/api/<device_id>', methods=['GET'])
@login_required
def get_device(device_id):
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    # Credentials are only visible to admin or staff owner
    if not _can_view_credentials(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403
    # Enrich with owner_username
    if device.get('owner_id'):
        u = db.users.find_one({'_id': device['owner_id']}, {'username': 1})
        if u:
            device['owner_username'] = u.get('username')
    return jsonify(_serialize_device(device))


@devices_bp.route('/api/<device_id>', methods=['PUT'])
@login_required
def update_device(device_id):
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    update = {}

    # Name
    if 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'name cannot be empty'}), 400
        update['name'] = name

    # Optional simple fields
    if 'manufacturer' in data:
        update['manufacturer'] = (data.get('manufacturer') or '').strip() or None
    if 'country_of_manufacture' in data:
        update['country_of_manufacture'] = (data.get('country_of_manufacture') or '').strip() or None
    if 'barcode' in data:
        update['barcode'] = (data.get('barcode') or '').strip() or None
    if 'serial_number' in data:
        update['serial_number'] = (data.get('serial_number') or '').strip() or None
    if 'description' in data:
        update['description'] = (data.get('description') or '').strip() or None

    # Networks
    if 'network_types' in data:
        networks = data.get('network_types')
        if networks is None:
            update['network_types'] = []
        elif isinstance(networks, list):
            cleaned = []
            seen = set()
            for n in networks:
                s = str(n).strip()
                if not s:
                    continue
                if s not in ALLOWED_NETWORKS:
                    return jsonify({'error': f'Invalid network type: {s}'}), 400
                if s not in seen:
                    seen.add(s)
                    cleaned.append(s)
            update['network_types'] = cleaned
        else:
            return jsonify({'error': 'network_types must be an array'}), 400

    # Custom fields
    if 'custom_fields' in data:
        custom_fields = data.get('custom_fields')
        if custom_fields is not None and not isinstance(custom_fields, dict):
            return jsonify({'error': 'custom_fields must be an object'}), 400
        if custom_fields:
            # Sanitize keys: only alphanumeric and underscore
            custom_fields = {k.replace(' ', '_'): v for k, v in custom_fields.items() if k}
        update['custom_fields'] = custom_fields or {}

    # Owner (admin-only)
    if current_user.role == 'admin' and ('owner_user_id' in data or 'owner_username' in data):
        owner_oid = None
        owner_id_str = (data.get('owner_user_id') or '').strip()
        owner_username = (data.get('owner_username') or '').strip()
        owner_user = None
        if owner_id_str:
            owner_oid = _obj_id(owner_id_str)
            if not owner_oid:
                return jsonify({'error': 'Invalid owner_user_id'}), 400
            owner_user = db.users.find_one({'_id': owner_oid})
        elif owner_username:
            owner_user = db.users.find_one({'username': owner_username})
            if not owner_user:
                return jsonify({'error': 'Owner username not found'}), 404
            owner_oid = owner_user['_id']
        if not owner_user:
            return jsonify({'error': 'Owner user not found'}), 404
        if owner_user.get('role') != 'staff':
            return jsonify({'error': 'Owner must be a staff user'}), 400
        update['owner_id'] = owner_oid

    if not update:
        return jsonify({'error': 'No valid fields to update'}), 400

    update['updated_at'] = datetime.utcnow()
    update['updated_by'] = str(current_user.get_id())
    db.devices.update_one({'_id': did}, {'$set': update})
    device = db.devices.find_one({'_id': did})
    if device.get('owner_id'):
        u = db.users.find_one({'_id': device['owner_id']}, {'username': 1})
        if u:
            device['owner_username'] = u.get('username')
    return jsonify({'device': _serialize_device(device)})


@devices_bp.route('/api/<device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403
    res = db.devices.delete_one({'_id': did})
    # Cascade delete credentials for this device
    db.device_logins.delete_many({'device_id': did})
    if res.deleted_count == 0:
        return jsonify({'error': 'Device not found'}), 404
    return '', 204


@devices_bp.route('/<device_id>/assign-users', methods=['PUT'])
@login_required
@staff_required
def assign_users(device_id):
    """
    Asigna uno o varios usuarios a un dispositivo.
    ---
    tags:
      - devices
    parameters:
      - in: path
        name: device_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - assigned_user_ids
          properties:
            assigned_user_ids:
              type: array
              items:
                type: string
    responses:
      200:
        description: Lista final de usuarios asignados
      400:
        description: Datos inválidos
      403:
        description: Prohibido
      404:
        description: Dispositivo no encontrado
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    usernames = data.get('assigned_usernames', None)
    ids = data.get('assigned_user_ids', None)

    if isinstance(usernames, list):
        # By usernames
        if len(usernames) == 0:
            valid_oids = []
        else:
            # Trim and filter empties
            names = [str(u).strip() for u in usernames if str(u).strip()]
            if not names:
                valid_oids = []
            else:
                users = list(db.users.find({'username': {'$in': names}}, {'_id': 1, 'username': 1}))
                found_names = {u['username'] for u in users}
                missing = [n for n in names if n not in found_names]
                if missing:
                    return jsonify({'error': f"Usernames not found: {', '.join(missing)}"}), 400
                # preserve order and dedupe by username
                seen = set()
                valid_oids = []
                by_name = {u['username']: u['_id'] for u in users}
                for n in names:
                    if n in seen:
                        continue
                    seen.add(n)
                    valid_oids.append(by_name[n])
    elif isinstance(ids, list):
        # By IDs (backward-compat)
        if len(ids) == 0:
            valid_oids = []
        else:
            oids = []
            for s in ids:
                oid = _obj_id(s)
                if not oid:
                    return jsonify({'error': f'Invalid user id: {s}'}), 400
                oids.append(oid)
            # Ensure users exist
            count = db.users.count_documents({'_id': {'$in': oids}})
            if count != len(oids):
                return jsonify({'error': 'One or more users do not exist'}), 400
            # Deduplicate preserving order
            seen = set()
            valid_oids = []
            for oid in oids:
                if oid in seen:
                    continue
                seen.add(oid)
                valid_oids.append(oid)
    else:
        return jsonify({'error': 'Provide assigned_usernames or assigned_user_ids as a list'}), 400

    update = {
        'assigned_users': valid_oids,
        'updated_at': datetime.utcnow(),
        'updated_by': str(current_user.get_id()),
    }
    # Optional: keep backward compat by also setting assigned_to when exactly one
    if len(valid_oids) == 1:
        update['assigned_to'] = valid_oids[0]
    else:
        update['assigned_to'] = None

    db.devices.update_one({'_id': did}, {'$set': update})
    device = db.devices.find_one({'_id': did})
    return jsonify({'device': _serialize_device(device)})


@devices_bp.route('/<device_id>/credentials', methods=['GET'])
@login_required
def list_credentials(device_id):
    """
    Lista las credenciales en texto plano de un dispositivo.
    ---
    tags:
      - devices
    parameters:
      - in: path
        name: device_id
        required: true
        type: string
    responses:
      200:
        description: Lista de credenciales
      403:
        description: Prohibido
      404:
        description: Dispositivo no encontrado
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_view_credentials(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    creds = list(db.device_logins.find({'device_id': did}))
    out = []
    for c in creds:
        c['_id'] = str(c['_id'])
        c['device_id'] = str(c['device_id'])
        c['type'] = c.get('type') or 'userpass'
        # Flag encrypted credentials (text or files)
        if c.get('encrypted') or c.get('payload_b64'):
            c['is_encrypted'] = True
            # Determine encryption source: client vs server
            if c.get('payload_b64') and isinstance(c.get('meta'), dict) and not c['meta'].get('server'):
                c['enc_source'] = 'client'
            else:
                c['enc_source'] = 'server'
        else:
            c['is_encrypted'] = False
        if c['type'] == 'certificate':
            files = c.get('files') or []
            norm_files = []
            for f in files:
                try:
                    fid = f.get('gfs_id')
                    fid_str = str(fid) if isinstance(fid, ObjectId) else str(ObjectId(fid))
                except Exception:
                    fid_str = str(f.get('gfs_id'))
                norm_files.append({
                    'gfs_id': fid_str,
                    'filename': f.get('filename'),
                    'content_type': f.get('content_type'),
                    'length': f.get('length'),
                    'encrypted': bool(f.get('encrypted')),
                    'enc_meta': f.get('enc_meta'),
                    'enc_source': ('client' if (f.get('enc_meta') and not (isinstance(f.get('enc_meta'), dict) and f['enc_meta'].get('server'))) else ('server' if f.get('encrypted') else None)),
                    'download_url': url_for('devices.download_credential_file', device_id=device_id, file_id=fid_str)
                })
            c['files'] = norm_files
        out.append(c)
    return jsonify({'credentials': out})


@devices_bp.route('/<device_id>/credentials/manage', methods=['GET'])
@login_required
def manage_credentials_page(device_id):
    """
    Página de gestión de credenciales para un dispositivo concreto.
    No aparece en el menú; acceso directo por URL o botones contextuales.
    Visible para admin y para el owner (staff) del dispositivo.
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_view_credentials(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403
    # Renderiza la página; la información detallada del dispositivo/credenciales se carga vía AJAX
    # Expose whether this user uses local-only key encryption (client-side)
    user_local_key = getattr(current_user, 'local_key', False)
    can_edit = _can_edit_device(current_user, device)
    return render_template('devices/credentials.html', device_id=str(device_id), user_local_key=bool(user_local_key), can_edit=bool(can_edit))


@devices_bp.route('/<device_id>/credentials', methods=['POST'])
@login_required
@staff_required
def upsert_credential(device_id):
    """
    Crea o actualiza una credencial (usuario/contraseña) en texto plano para un dispositivo.
    ---
    tags:
      - devices
    consumes:
      - application/json
    parameters:
      - in: path
        name: device_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
            note:
              type: string
    responses:
      200:
        description: Credencial creada/actualizada
      400:
        description: Datos inválidos
      403:
        description: Prohibido
      404:
        description: Dispositivo no encontrado
      409:
        description: Conflicto de duplicado
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    cred_type = (data.get('type') or 'userpass').strip()

    now = datetime.utcnow()

    if cred_type == 'userpass':
        username = (data.get('username') or '').strip()
        password = data.get('password')
        note = data.get('note')
        if not username or password is None:
            return jsonify({'error': 'username and password are required'}), 400
        # Server-side encrypted storage; dedupe by HMAC tag of username
        tag = hmac_tag(username, str(did))
        existing = db.device_logins.find_one({'device_id': did, 'type': 'userpass', '$or': [
            {'username': username}, {'tag_username': tag}
        ]})
        if existing:
            payload_b64, meta = encrypt_json({'username': username, 'password': password, 'note': note})
            db.device_logins.update_one({'_id': existing['_id']}, {'$set': {
                'type': 'userpass',
                'encrypted': True,
                'payload_b64': payload_b64,
                'meta': meta,
                'tag_username': tag,
                'username': None,
                'password': None,
                'note': None,
                'updated_at': now,
                'updated_by': str(current_user.get_id()),
            }})
            doc = db.device_logins.find_one({'_id': existing['_id']})
        else:
            payload_b64, meta = encrypt_json({'username': username, 'password': password, 'note': note})
            try:
                ins = db.device_logins.insert_one({
                    'device_id': did,
                    'type': 'userpass',
                    'encrypted': True,
                    'payload_b64': payload_b64,
                    'meta': meta,
                    'tag_username': tag,
                    'created_at': now,
                    'created_by': str(current_user.get_id()),
                    'updated_at': now,
                    'updated_by': str(current_user.get_id()),
                })
            except Exception:
                return jsonify({'error': 'Duplicate credential for this device and username'}), 409
            doc = db.device_logins.find_one({'_id': ins.inserted_id})
        doc['_id'] = str(doc['_id'])
        doc['device_id'] = str(doc['device_id'])
        return jsonify({'credential': doc}), 200

    elif cred_type == 'token':
        token = data.get('token')
        if token is None or str(token) == '':
            return jsonify({'error': 'token is required'}), 400
        label = (data.get('label') or '').strip() or None
        note = data.get('note')
        payload_b64, meta = encrypt_json({'token': token, 'label': label, 'note': note})
        ins = db.device_logins.insert_one({
            'device_id': did,
            'type': 'token',
            'encrypted': True,
            'payload_b64': payload_b64,
            'meta': meta,
            'created_at': now,
            'created_by': str(current_user.get_id()),
            'updated_at': now,
            'updated_by': str(current_user.get_id()),
        })
        doc = db.device_logins.find_one({'_id': ins.inserted_id})
        doc['_id'] = str(doc['_id'])
        doc['device_id'] = str(doc['device_id'])
        return jsonify({'credential': doc}), 200

    else:
        return jsonify({'error': 'Unsupported type for this endpoint. Use /credentials/upload for files.'}), 400


@devices_bp.route('/<device_id>/credentials/upload', methods=['POST'])
@login_required
@staff_required
def upload_credential_files(device_id):
    """
    Crea una credencial basada en archivos (p.ej., certificados) usando multipart/form-data.
    Campos:
      - type: debe ser 'certificate'
      - label: opcional
      - note: opcional
      - files: uno o varios archivos
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    ctype = (request.form.get('type') or '').strip() or 'certificate'
    if ctype != 'certificate':
        return jsonify({'error': 'type must be certificate'}), 400

    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'At least one file is required'}), 400

    label = (request.form.get('label') or '').strip() or None
    note = request.form.get('note')
    # Client-side encryption support
    encrypted_flag = str(request.form.get('encrypted') or '').lower() in ['1', 'true', 'yes']
    # Optional encrypted credential payload for label/note
    cred_payload_b64 = request.form.get('cred_payload_b64')
    cred_meta = None
    if request.form.get('cred_meta'):
        try:
            cred_meta = json.loads(request.form.get('cred_meta'))
        except Exception:
            cred_meta = None
    # Optional per-file encryption metadata list, aligned with files order
    enc_meta_list = None
    if request.form.get('enc_meta_list'):
        try:
            enc_meta_list = json.loads(request.form.get('enc_meta_list'))
        except Exception:
            enc_meta_list = None

    saved = []
    for idx, f in enumerate(files):
        if not f or f.filename == '':
            continue
        data = f.stream.read()
        f.stream.seek(0)
        # Build GridFS metadata
        gfs_meta = {
            'device_id': str(did),
            'type': 'certificate',
            'label': label,
            'uploader': str(current_user.get_id()),
        }
        if encrypted_flag:
            # Client provided encrypted bytes in FormData; just propagate meta
            gfs_meta['encrypted'] = True
            if isinstance(enc_meta_list, list) and idx < len(enc_meta_list):
                try:
                    gfs_meta['enc_meta'] = enc_meta_list[idx]
                except Exception:
                    pass
        else:
            # Server-side encrypt the file bytes before storing
            try:
                cipher_bytes, meta = encrypt_bytes(data)
                data = cipher_bytes
                gfs_meta['encrypted'] = True
                gfs_meta['enc_meta'] = meta
            except Exception:
                return jsonify({'error': 'Failed to encrypt file'}), 500
        file_id = fs.put(io.BytesIO(data), filename=f.filename, content_type=f.mimetype, metadata=gfs_meta)
        saved.append({
            'gfs_id': file_id,
            'filename': f.filename,
            'content_type': f.mimetype,
            'length': len(data),
            'encrypted': True if (encrypted_flag or gfs_meta.get('enc_meta')) else False,
            'enc_meta': gfs_meta.get('enc_meta'),
        })

    if not saved:
        return jsonify({'error': 'No valid files uploaded'}), 400

    now = datetime.utcnow()
    # Build doc; if client didn't encrypt label/note, encrypt server-side
    doc = {
        'device_id': did,
        'type': 'certificate',
        'files': saved,
        'created_at': now,
        'created_by': str(current_user.get_id()),
        'updated_at': now,
        'updated_by': str(current_user.get_id()),
    }
    if cred_payload_b64 and cred_meta is not None:
        doc['encrypted'] = True
        doc['payload_b64'] = cred_payload_b64
        doc['meta'] = cred_meta
    elif not encrypted_flag:
        # Encrypt label/note on server
        payload_b64, meta = encrypt_json({'label': label, 'note': note})
        doc['encrypted'] = True
        doc['payload_b64'] = payload_b64
        doc['meta'] = meta
    else:
        # plaintext fallback for label/note if client used encrypted files but no cred_payload
        doc['label'] = label
        doc['note'] = note
    ins = db.device_logins.insert_one(doc)
    doc = db.device_logins.find_one({'_id': ins.inserted_id})
    doc['_id'] = str(doc['_id'])
    doc['device_id'] = str(doc['device_id'])
    return jsonify({'credential': doc}), 201


@devices_bp.route('/<device_id>/credentials/encrypted', methods=['POST'])
@login_required
@staff_required
def upsert_credential_encrypted(device_id):
    """
    Crea una credencial encriptada en el cliente (userpass o token) y la almacena como blob cifrado.
    El servidor no conoce las claves ni el contenido.
    Body JSON:
      - type: 'userpass' | 'token'
      - payload_b64: base64 del JSON cifrado
      - meta: objeto JSON con metadatos de cifrado (p. ej. algoritmo, iv, kdf)
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    cred_type = (data.get('type') or '').strip()
    payload_b64 = data.get('payload_b64')
    meta = data.get('meta')
    if cred_type not in ['userpass', 'token']:
        return jsonify({'error': 'Unsupported type for encrypted endpoint'}), 400
    if not payload_b64 or not isinstance(payload_b64, str):
        return jsonify({'error': 'payload_b64 is required'}), 400
    if meta is None:
        return jsonify({'error': 'meta is required'}), 400

    now = datetime.utcnow()
    doc = {
        'device_id': did,
        'type': cred_type,
        'encrypted': True,
        'payload_b64': payload_b64,
        'meta': meta,
        'created_at': now,
        'created_by': str(current_user.get_id()),
        'updated_at': now,
        'updated_by': str(current_user.get_id()),
    }
    ins = db.device_logins.insert_one(doc)
    out = db.device_logins.find_one({'_id': ins.inserted_id})
    out['_id'] = str(out['_id'])
    out['device_id'] = str(out['device_id'])
    return jsonify({'credential': out}), 201


@devices_bp.route('/<device_id>/credentials/file/<file_id>', methods=['GET'])
@login_required
def download_credential_file(device_id, file_id):
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_view_credentials(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    # Resolve file and ensure it belongs to this device
    try:
        fid = ObjectId(file_id)
        gridout = fs.get(fid)
    except Exception:
        return jsonify({'error': 'File not found'}), 404

    # Ensure the GridFS file is referenced by a certificate credential of this device
    linked = db.device_logins.find_one({'device_id': did, 'type': 'certificate', 'files.gfs_id': fid})
    if not linked:
        # Fallback: check GridFS metadata device_id
        meta_dev = None
        try:
            meta = getattr(gridout, 'metadata', {}) or {}
            meta_dev = meta.get('device_id')
        except Exception:
            meta_dev = None
        if str(meta_dev) != str(did):
            return jsonify({'error': 'File not found'}), 404

    data = gridout.read()
    # If server-encrypted, decrypt before sending
    try:
        meta = getattr(gridout, 'metadata', {}) or {}
        enc_meta = meta.get('enc_meta') or {}
        if meta.get('encrypted') and isinstance(enc_meta, dict) and enc_meta.get('server'):
            data = decrypt_bytes(data, enc_meta)
    except Exception:
        pass
    resp = send_file(
        io.BytesIO(data),
        mimetype=(getattr(gridout, 'content_type', None) or 'application/octet-stream'),
        as_attachment=True,
        download_name=(getattr(gridout, 'filename', None) or 'download'),
    )
    return resp


@devices_bp.route('/<device_id>/credentials/id/<cred_id>/reveal', methods=['GET'])
@login_required
def reveal_server_encrypted(device_id, cred_id):
    """Reveal decrypted content of a server-encrypted credential (JSON payload).
    Only admin or device owner (staff) can access.
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_view_credentials(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    try:
        cid = ObjectId(cred_id)
    except Exception:
        return jsonify({'error': 'Invalid credential id'}), 400

    doc = db.device_logins.find_one({'_id': cid, 'device_id': did})
    if not doc:
        return jsonify({'error': 'Credential not found'}), 404
    if not doc.get('encrypted') or not doc.get('payload_b64'):
        return jsonify({'error': 'Not encrypted or unsupported format'}), 400
    meta = doc.get('meta') or {}
    # Only reveal server-encrypted payloads (meta.server == True)
    if not isinstance(meta, dict) or not meta.get('server'):
        return jsonify({'error': 'Client-side encrypted content must be decrypted client-side'}), 400
    try:
        obj = decrypt_json(doc['payload_b64'], meta)
    except Exception:
        return jsonify({'error': 'Failed to decrypt'}), 500
    return jsonify({'data': obj})


@devices_bp.route('/<device_id>/credentials/id/<cred_id>', methods=['DELETE'])
@login_required
@staff_required
def delete_credential_by_id(device_id, cred_id):
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    try:
        cid = ObjectId(cred_id)
    except Exception:
        return jsonify({'error': 'Invalid credential id'}), 400

    doc = db.device_logins.find_one({'_id': cid, 'device_id': did})
    if not doc:
        return jsonify({'error': 'Credential not found'}), 404

    # If certificate, delete files from GridFS
    if doc.get('type') == 'certificate':
        for f in (doc.get('files') or []):
            fid = f.get('gfs_id')
            try:
                fs.delete(ObjectId(str(fid)))
            except Exception:
                pass

    db.device_logins.delete_one({'_id': cid})
    return '', 204


@devices_bp.route('/<device_id>/credentials/<username>', methods=['DELETE'])
@login_required
@staff_required
def delete_credential(device_id, username):
    """
    Elimina una credencial por usuario para un dispositivo.
    ---
    tags:
      - devices
    parameters:
      - in: path
        name: device_id
        required: true
        type: string
      - in: path
        name: username
        required: true
        type: string
    responses:
      204:
        description: Eliminado
      403:
        description: Prohibido
      404:
        description: Dispositivo o credencial no encontrado
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    res = db.device_logins.delete_one({'device_id': did, 'username': username})
    if res.deleted_count == 0:
        return jsonify({'error': 'Credential not found'}), 404
    return '', 204


@devices_bp.route('/<device_id>/credentials/<username>', methods=['PUT'])
@login_required
@staff_required
def update_credential(device_id, username):
    """
    Actualiza una credencial existente por username para un dispositivo.
    Permite cambiar password y note, y opcionalmente renombrar el username.
    ---
    tags:
      - devices
    consumes:
      - application/json
    parameters:
      - in: path
        name: device_id
        required: true
        type: string
      - in: path
        name: username
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            password: { type: string }
            note: { type: string }
            new_username: { type: string }
    responses:
      200: { description: Credencial actualizada }
      400: { description: Datos inválidos }
      403: { description: Prohibido }
      404: { description: Dispositivo o credencial no encontrado }
      409: { description: Conflicto de duplicado }
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_edit_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    update = {}
    if 'password' in data:
        update['password'] = data.get('password')
    if 'note' in data:
        update['note'] = data.get('note')
    new_username = (data.get('new_username') or '').strip()

    now = datetime.utcnow()
    update['updated_at'] = now
    update['updated_by'] = str(current_user.get_id())
    # Ensure type for username-based credentials
    update['type'] = 'userpass'

    # First ensure credential exists (only userpass or legacy without type)
    existing = db.device_logins.find_one({'device_id': did, 'username': username, 'type': {'$in': [None, 'userpass']}})
    if not existing:
        return jsonify({'error': 'Credential not found'}), 404

    # If renaming username
    if new_username and new_username != username:
        # Check duplicate for target username among userpass credentials
        dup = db.device_logins.find_one({'device_id': did, 'username': new_username, 'type': {'$in': [None, 'userpass']}})
        if dup:
            return jsonify({'error': 'Duplicate credential for this device and username'}), 409
        # Update with new username
        update['username'] = new_username

    db.device_logins.update_one({'_id': existing['_id']}, {'$set': update})
    doc = db.device_logins.find_one({'_id': existing['_id']})
    doc['_id'] = str(doc['_id'])
    doc['device_id'] = str(doc['device_id'])
    return jsonify({'credential': doc}), 200


@devices_bp.route('/<device_id>/owner', methods=['PUT'])
@login_required
@admin_required
def set_owner(device_id):
    """
    Establece el propietario (staff) del dispositivo.
    ---
    tags:
      - devices
    parameters:
      - in: path
        name: device_id
        required: true
        type: string
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - owner_user_id
          properties:
            owner_user_id:
              type: string
    responses:
      200: { description: Propietario actualizado }
      400: { description: Datos inválidos }
      404: { description: Dispositivo o usuario no encontrado }
    """
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    data = request.get_json(silent=True) or {}
    owner_id_str = data.get('owner_user_id')
    owner_oid = _obj_id(owner_id_str) if owner_id_str else None
    if not owner_oid:
        return jsonify({'error': 'owner_user_id is required'}), 400
    user = db.users.find_one({'_id': owner_oid})
    if not user:
        return jsonify({'error': 'Owner user not found'}), 404
    if user.get('role') != 'staff':
        return jsonify({'error': 'Owner must be a staff user'}), 400

    db.devices.update_one({'_id': did}, {'$set': {
        'owner_id': owner_oid,
        'updated_at': datetime.utcnow(),
        'updated_by': str(current_user.get_id()),
    }})
    device = db.devices.find_one({'_id': did})
    return jsonify({'device': _serialize_device(device)})


# ─────────────────────────────────────────────────────────────────────────────
# Device Logs (Maintenance & Event Timeline)
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_LOG_TYPES = {'maintenance', 'firmware_update', 'reboot', 'note', 'custom'}


def _serialize_log(log: dict) -> dict:
    """Serialize a device log document for JSON response."""
    if not log:
        return None
    return {
        '_id': str(log['_id']),
        'device_id': str(log.get('device_id', '')),
        'event_type': log.get('event_type', 'note'),
        'title': log.get('title', ''),
        'description': log.get('description', ''),
        'metadata': log.get('metadata', {}),
        'created_at': log.get('created_at').isoformat() if log.get('created_at') else None,
        'created_by': log.get('created_by', ''),
        'created_by_username': log.get('created_by_username', ''),
        'updated_at': log.get('updated_at').isoformat() if log.get('updated_at') else None,
    }


def _can_edit_log(user, log: dict, device: dict) -> bool:
    """Check if user can edit/delete a log entry."""
    if user.role == 'admin':
        return True
    if _is_owner(user, device):
        return True
    # Creator can edit their own logs
    if log.get('created_by') == str(user.get_id()):
        return True
    return False


@devices_bp.route('/<device_id>/logs', methods=['GET'])
@login_required
def list_device_logs(device_id):
    """List all log entries for a device."""
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not _can_view_device(current_user, device):
        return jsonify({'error': 'Forbidden'}), 403

    # Pagination
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 50))))
    skip = (page - 1) * per_page

    # Filter by event_type (optional)
    query = {'device_id': did}
    event_type = request.args.get('event_type')
    if event_type and event_type in ALLOWED_LOG_TYPES:
        query['event_type'] = event_type

    total = db.device_logs.count_documents(query)
    logs = list(db.device_logs.find(query).sort('created_at', -1).skip(skip).limit(per_page))

    # Enrich with creator username
    creator_ids = list(set(log.get('created_by') for log in logs if log.get('created_by')))
    creator_oids = [_obj_id(cid) for cid in creator_ids if _obj_id(cid)]
    users_map = {}
    if creator_oids:
        users = db.users.find({'_id': {'$in': creator_oids}}, {'username': 1})
        users_map = {str(u['_id']): u.get('username', '') for u in users}
    for log in logs:
        log['created_by_username'] = users_map.get(log.get('created_by', ''), '')

    return jsonify({
        'logs': [_serialize_log(l) for l in logs],
        'total': total,
        'page': page,
        'per_page': per_page,
    })


@devices_bp.route('/<device_id>/logs', methods=['POST'])
@login_required
def create_device_log(device_id):
    """Create a new log entry for a device."""
    did = _obj_id(device_id)
    if not did:
        return jsonify({'error': 'Invalid device_id'}), 400
    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    # Only owner or admin can create logs
    if not (current_user.role == 'admin' or _is_owner(current_user, device)):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400

    event_type = (data.get('event_type') or 'note').strip()
    if event_type not in ALLOWED_LOG_TYPES:
        return jsonify({'error': f'Invalid event_type. Allowed: {", ".join(ALLOWED_LOG_TYPES)}'}), 400

    description = (data.get('description') or '').strip() or None
    metadata = data.get('metadata') or {}
    if not isinstance(metadata, dict):
        metadata = {}

    now = datetime.utcnow()
    doc = {
        'device_id': did,
        'event_type': event_type,
        'title': title,
        'description': description,
        'metadata': metadata,
        'created_at': now,
        'created_by': str(current_user.get_id()),
        'updated_at': now,
    }
    result = db.device_logs.insert_one(doc)
    doc['_id'] = result.inserted_id

    # Get creator username
    user = db.users.find_one({'_id': _obj_id(str(current_user.get_id()))}, {'username': 1})
    doc['created_by_username'] = user.get('username', '') if user else ''

    return jsonify({'log': _serialize_log(doc)}), 201


@devices_bp.route('/<device_id>/logs/<log_id>', methods=['PUT'])
@login_required
def update_device_log(device_id, log_id):
    """Update a log entry."""
    did = _obj_id(device_id)
    lid = _obj_id(log_id)
    if not did or not lid:
        return jsonify({'error': 'Invalid device_id or log_id'}), 400

    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    log = db.device_logs.find_one({'_id': lid, 'device_id': did})
    if not log:
        return jsonify({'error': 'Log not found'}), 404

    if not _can_edit_log(current_user, log, device):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    update = {}

    if 'title' in data:
        title = (data.get('title') or '').strip()
        if not title:
            return jsonify({'error': 'title cannot be empty'}), 400
        update['title'] = title

    if 'event_type' in data:
        event_type = (data.get('event_type') or '').strip()
        if event_type not in ALLOWED_LOG_TYPES:
            return jsonify({'error': f'Invalid event_type. Allowed: {", ".join(ALLOWED_LOG_TYPES)}'}), 400
        update['event_type'] = event_type

    if 'description' in data:
        update['description'] = (data.get('description') or '').strip() or None

    if 'metadata' in data:
        metadata = data.get('metadata') or {}
        if isinstance(metadata, dict):
            update['metadata'] = metadata

    if not update:
        return jsonify({'error': 'No valid fields to update'}), 400

    update['updated_at'] = datetime.utcnow()
    db.device_logs.update_one({'_id': lid}, {'$set': update})

    log = db.device_logs.find_one({'_id': lid})
    user = db.users.find_one({'_id': _obj_id(log.get('created_by', ''))}, {'username': 1})
    log['created_by_username'] = user.get('username', '') if user else ''

    return jsonify({'log': _serialize_log(log)})


@devices_bp.route('/<device_id>/logs/<log_id>', methods=['DELETE'])
@login_required
def delete_device_log(device_id, log_id):
    """Delete a log entry."""
    did = _obj_id(device_id)
    lid = _obj_id(log_id)
    if not did or not lid:
        return jsonify({'error': 'Invalid device_id or log_id'}), 400

    device = db.devices.find_one({'_id': did})
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    log = db.device_logs.find_one({'_id': lid, 'device_id': did})
    if not log:
        return jsonify({'error': 'Log not found'}), 404

    if not _can_edit_log(current_user, log, device):
        return jsonify({'error': 'Forbidden'}), 403

    db.device_logs.delete_one({'_id': lid})
    return jsonify({'deleted': True})
