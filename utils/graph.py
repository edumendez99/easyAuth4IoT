from flask import Blueprint, jsonify, render_template, redirect, url_for
from flask_login import login_required, current_user
from bson import ObjectId
from .database import db
from .auth import staff_required

graph_bp = Blueprint('graph', __name__)


def _obj_id(s):
    try:
        return ObjectId(s)
    except Exception:
        return None


def _user_type(role):
    if role == 'admin':
        return 'user_admin'
    if role == 'staff':
        return 'user_staff'
    return 'user'


@graph_bp.route('/')
@login_required
@staff_required
def graph_page():
    return render_template('graph/view.html')


@graph_bp.route('/api')
@login_required
@staff_required
def graph_api():
    """
    Returns graph data scoped to what the current user is allowed to see.
    Admin: all entities.
    Staff: own devices + users assigned to those + credentials/files on those + own config templates.
    """
    uid = _obj_id(str(current_user.get_id()))
    is_admin = current_user.role == 'admin'

    nodes = []
    links = []
    seen_node_ids = set()

    def add_node(node_id, ntype, label, data=None):
        if node_id not in seen_node_ids:
            seen_node_ids.add(node_id)
            nodes.append({'id': node_id, 'type': ntype, 'label': label, 'data': data or {}})

    def add_link(source, target, relation):
        links.append({'source': source, 'target': target, 'relation': relation})

    # ─── Users ───────────────────────────────────────────────────────────────
    if is_admin:
        all_users = list(db.users.find({}, {'password': 0}))
    else:
        # Staff only sees themselves
        all_users = list(db.users.find({'_id': uid}, {'password': 0}))

    user_map = {}
    for u in all_users:
        user_id = str(u['_id'])
        user_map[user_id] = u
        ntype = _user_type(u.get('role', 'user'))
        add_node(f'user_{user_id}', ntype, u.get('username', '—'), {
            'email': u.get('email'),
            'role': u.get('role'),
            'is_active': u.get('is_active', True),
        })

    # ─── Devices ─────────────────────────────────────────────────────────────
    if is_admin:
        all_devices = list(db.devices.find({}))
    else:
        all_devices = list(db.devices.find({'owner_id': uid}))

    device_ids = []
    for device in all_devices:
        device_id = str(device['_id'])
        device_ids.append(device['_id'])
        add_node(f'device_{device_id}', 'device', device.get('name', '—'), {
            'manufacturer': device.get('manufacturer'),
            'networks': device.get('network_types', []),
            'serial_number': device.get('serial_number'),
        })

        # Owner link
        owner_id = str(device.get('owner_id') or '')
        if owner_id and f'user_{owner_id}' in seen_node_ids:
            add_link(f'user_{owner_id}', f'device_{device_id}', 'owner')

        # Assigned users — only expose users the current user can already see
        assigned = list(device.get('assigned_users') or [])
        if device.get('assigned_to'):
            assigned.append(device['assigned_to'])
        for auid in assigned:
            auid_str = str(auid)
            if is_admin:
                # Ensure the assigned user node exists (may not be in all_users if filtered)
                if f'user_{auid_str}' not in seen_node_ids:
                    u = db.users.find_one({'_id': auid}, {'password': 0})
                    if u:
                        ntype = _user_type(u.get('role', 'user'))
                        add_node(f'user_{auid_str}', ntype, u.get('username', '—'), {
                            'email': u.get('email'),
                            'role': u.get('role'),
                            'is_active': u.get('is_active', True),
                        })
                add_link(f'user_{auid_str}', f'device_{device_id}', 'assigned')
            # Staff: only show assigned link if assigned user is themselves
            elif auid_str == str(uid):
                add_link(f'user_{auid_str}', f'device_{device_id}', 'assigned')

    # ─── Credentials ─────────────────────────────────────────────────────────
    if device_ids:
        creds = list(db.device_logins.find({'device_id': {'$in': device_ids}}))
        for cred in creds:
            cred_id = str(cred['_id'])
            device_id = str(cred['device_id'])
            label = cred.get('label') or cred.get('username') or cred.get('type', 'cred')
            add_node(f'cred_{cred_id}', 'credential', label, {
                'cred_type': cred.get('type'),
                'expires_at': cred.get('expires_at').isoformat() if cred.get('expires_at') else None,
                'is_encrypted': bool(cred.get('payload_b64') or cred.get('encrypted')),
            })
            add_link(f'device_{device_id}', f'cred_{cred_id}', 'has_credential')

    # ─── Device files ─────────────────────────────────────────────────────────
    if device_ids:
        d_files = list(db.device_files.find({'device_id': {'$in': device_ids}}))
        for f in d_files:
            fid = str(f['_id'])
            device_id = str(f['device_id'])
            add_node(f'dfile_{fid}', 'device_file', f.get('filename', 'archivo'), {
                'size': f.get('size', 0),
                'content_type': f.get('content_type'),
            })
            add_link(f'device_{device_id}', f'dfile_{fid}', 'has_file')

    # ─── Config templates ─────────────────────────────────────────────────────
    if is_admin:
        tpl_query = {}
    else:
        tpl_query = {'owner_id': uid}

    templates = list(db.config_templates.find(tpl_query))
    for t in templates:
        tid = str(t['_id'])
        owner_id = str(t.get('owner_id') or '')
        add_node(f'ctpl_{tid}', 'config_template', t.get('name', '—'), {
            'file_type': t.get('file_type'),
            'description': t.get('description'),
        })
        if owner_id and f'user_{owner_id}' in seen_node_ids:
            add_link(f'user_{owner_id}', f'ctpl_{tid}', 'owns_template')

    # ─── Config template files ────────────────────────────────────────────────
    if is_admin:
        cfile_query = {}
    else:
        cfile_query = {'owner_id': uid}

    cfiles = list(db.config_template_files.find(cfile_query))
    for f in cfiles:
        fid = str(f['_id'])
        owner_id = str(f.get('owner_id') or '')
        add_node(f'cfile_{fid}', 'config_file', f.get('name') or f.get('filename', 'archivo'), {
            'filename': f.get('filename'),
            'size': f.get('size', 0),
        })
        if owner_id and f'user_{owner_id}' in seen_node_ids:
            add_link(f'user_{owner_id}', f'cfile_{fid}', 'owns_config_file')

    stats = {
        'users': sum(1 for n in nodes if n['type'] in ('user_admin', 'user_staff', 'user')),
        'devices': sum(1 for n in nodes if n['type'] == 'device'),
        'credentials': sum(1 for n in nodes if n['type'] == 'credential'),
        'files': sum(1 for n in nodes if n['type'] in ('device_file', 'config_file')),
        'templates': sum(1 for n in nodes if n['type'] == 'config_template'),
    }

    return jsonify({'nodes': nodes, 'links': links, 'stats': stats})
