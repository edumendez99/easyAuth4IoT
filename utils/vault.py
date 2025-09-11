from flask import Blueprint, jsonify, render_template, request, send_file
from flask_login import login_required, current_user
from bson import ObjectId
from datetime import datetime
from werkzeug.utils import secure_filename
import io

from .database import db, fs
from .crypto_server import encrypt_json, decrypt_json, encrypt_bytes, decrypt_bytes
from .auth import staff_required

vault_bp = Blueprint('vault', __name__)


def _obj_id(x):
    try:
        return ObjectId(x)
    except Exception:
        return None


@vault_bp.route('/', methods=['GET'])
@login_required
def list_page():
    """Render main page for managing personal vault items."""
    user_local_key = getattr(current_user, 'local_key', False)
    return render_template('vault/list.html', user_local_key=bool(user_local_key))


@vault_bp.route('/api', methods=['GET'])
@login_required
def list_items():
    """List vault items belonging to the current user.

    Items can be plaintext or encrypted blobs. We return minimal info so
    client can decide how to render/decrypt.
    """
    uid = _obj_id(current_user.get_id())
    qtype = (request.args.get('type') or '').strip()
    qtext = (request.args.get('q') or '').strip()
    query = {'owner_id': uid}
    if qtype and qtype != 'all':
        query['type'] = qtype
    items = list(db.vault_items.find(query).sort('updated_at', -1))
    out = []
    # Optional text search: include plaintext and server-encrypted (decrypt to search). Client-encrypted cannot be searched server-side.
    if qtext:
        lt = qtext.lower()

        def _haystack_plain(doc: dict) -> str:
            fields = []
            for k in ['title','label','username','password','note','token','full_name','email','phone','address','doc_id','issuer','account','url']:
                v = doc.get(k)
                if isinstance(v, str):
                    fields.append(v)
            for f in (doc.get('files') or []):
                fn = f.get('filename')
                if isinstance(fn, str):
                    fields.append(fn)
            return ' '.join(fields).lower()

        def _haystack_dec(doc: dict) -> str:
            try:
                meta = doc.get('meta') or {}
                if not (isinstance(meta, dict) and meta.get('server') and doc.get('payload_b64')):
                    return ''
                obj = decrypt_json(doc.get('payload_b64'), meta)
                fields = []
                for k in ['title','label','username','password','note','token','full_name','email','phone','address','doc_id','issuer','account','secret','url']:
                    v = obj.get(k) if isinstance(obj, dict) else None
                    if isinstance(v, str):
                        fields.append(v)
                return ' '.join(fields).lower()
            except Exception:
                return ''

        filtered = []
        for doc in items:
            if not (doc.get('encrypted') or doc.get('payload_b64')):
                hay = _haystack_plain(doc)
                if hay and lt in hay:
                    filtered.append(doc)
            else:
                # Try server-side dec search
                hay = _haystack_dec(doc)
                if hay and lt in hay:
                    filtered.append(doc)
        items = filtered

    for it in items:
        it['_id'] = str(it['_id'])
        it['owner_id'] = str(it['owner_id'])
        # Normalize files: list of { gfs_id, filename, length, content_type, encrypted, enc_meta }
        files = []
        for f in (it.get('files') or []):
            try:
                files.append({
                    'gfs_id': str(f['gfs_id']) if isinstance(f.get('gfs_id'), ObjectId) else str(f.get('gfs_id')),
                    'filename': f.get('filename'),
                    'length': f.get('length'),
                    'content_type': f.get('content_type'),
                    'encrypted': bool(f.get('encrypted')),
                    'enc_meta': f.get('enc_meta') or None,
                    'download_url': f"/vault/file/{str(f['gfs_id'])}",
                })
            except Exception:
                continue
        if files:
            it['files'] = files
        # is_encrypted convenience flag
        if it.get('encrypted') or it.get('payload_b64'):
            it['is_encrypted'] = True
            # If server-encrypted, auto-decrypt for default rendering and client-side search
            try:
                meta = it.get('meta') or {}
                if isinstance(meta, dict) and meta.get('server') and it.get('payload_b64'):
                    obj = decrypt_json(it.get('payload_b64'), meta)
                    it['_dec'] = obj
            except Exception:
                pass
        out.append(it)
    return jsonify({'items': out})


@vault_bp.route('/items', methods=['POST'])
@login_required
def create_item_plain():
    """Create a vault item but store encrypted server-side using the DB key.

    Backward compatible with older clients that POST plaintext to /vault/items.
    """
    data = request.get_json(silent=True) or {}
    typ = (data.get('type') or '').strip() or 'password'
    # Build payload from provided fields except type
    payload = {k: v for k, v in data.items() if k != 'type'}
    now = datetime.utcnow()
    uid = _obj_id(current_user.get_id())
    payload['type'] = typ
    ct_b64, meta = encrypt_json(payload)
    doc = {
        'owner_id': uid,
        'type': typ,
        'encrypted': True,
        'payload_b64': ct_b64,
        'meta': meta,
        'created_at': now,
        'updated_at': now,
    }
    res = db.vault_items.insert_one(doc)
    out = db.vault_items.find_one({'_id': res.inserted_id})
    out['_id'] = str(out['_id'])
    out['owner_id'] = str(out['owner_id'])
    return jsonify({'item': out}), 201


@vault_bp.route('/items/server', methods=['POST'])
@login_required
def create_item_server_enc():
    """Create an encrypted vault item using server-side key (explicit endpoint)."""
    data = request.get_json(silent=True) or {}
    typ = (data.get('type') or '').strip() or 'password'
    payload = {k: v for k, v in data.items() if k != 'type'}
    uid = _obj_id(current_user.get_id())
    now = datetime.utcnow()
    payload['type'] = typ
    ct_b64, meta = encrypt_json(payload)
    doc = {
        'owner_id': uid,
        'type': typ,
        'encrypted': True,
        'payload_b64': ct_b64,
        'meta': meta,
        'created_at': now,
        'updated_at': now,
    }
    res = db.vault_items.insert_one(doc)
    out = db.vault_items.find_one({'_id': res.inserted_id})
    out['_id'] = str(out['_id'])
    out['owner_id'] = str(out['owner_id'])
    return jsonify({'item': out}), 201


@vault_bp.route('/items/encrypted', methods=['POST'])
@login_required
def create_item_encrypted():
    """Create an encrypted vault item (client-side encrypted JSON blob).

    Body JSON: { type, payload_b64, meta }
    Supported types: password, note, token, card, identity, ssh, pgp, totp, passkey, file_meta
    """
    data = request.get_json(silent=True) or {}
    typ = (data.get('type') or '').strip()
    payload_b64 = data.get('payload_b64')
    meta = data.get('meta')
    if not typ:
        return jsonify({'error': 'type is required'}), 400
    if not payload_b64 or not isinstance(payload_b64, str):
        return jsonify({'error': 'payload_b64 is required'}), 400
    if meta is None:
        return jsonify({'error': 'meta is required'}), 400

    now = datetime.utcnow()
    doc = {
        'owner_id': _obj_id(current_user.get_id()),
        'type': typ,
        'encrypted': True,
        'payload_b64': payload_b64,
        'meta': meta,
        'created_at': now,
        'updated_at': now,
    }
    res = db.vault_items.insert_one(doc)
    out = db.vault_items.find_one({'_id': res.inserted_id})
    out['_id'] = str(out['_id'])
    out['owner_id'] = str(out['owner_id'])
    return jsonify({'item': out}), 201


@vault_bp.route('/upload', methods=['POST'])
@login_required
def upload_files():
    """Upload one or more files as a new vault item of type 'file'.

    FormData:
      - type: 'file' (optional, default 'file')
      - encrypted: 'true'|'false'
      - files: one or multiple file parts
      - If encrypted == true:
          - cred_payload_b64: encrypted JSON with label/note
          - cred_meta: JSON string
          - enc_meta_list: JSON string array with per-file meta
        Else (plaintext):
          - label, note
    """
    typ = (request.form.get('type') or 'file').strip()
    if typ != 'file':
        return jsonify({'error': 'Unsupported type for upload'}), 400

    encrypted_flag = (request.form.get('encrypted') == 'true')
    label = request.form.get('label')
    note = request.form.get('note')
    url_plain = request.form.get('url')

    cred_payload_b64 = request.form.get('cred_payload_b64')
    cred_meta_raw = request.form.get('cred_meta')
    enc_meta_list_raw = request.form.get('enc_meta_list')

    try:
        cred_meta = None
        if cred_meta_raw:
            from json import loads
            cred_meta = loads(cred_meta_raw)
        enc_meta_list = None
        if enc_meta_list_raw:
            from json import loads
            enc_meta_list = loads(enc_meta_list_raw)
    except Exception:
        return jsonify({'error': 'Invalid metadata JSON'}), 400

    now = datetime.utcnow()
    owner_id = _obj_id(current_user.get_id())
    doc = {
        'owner_id': owner_id,
        'type': 'file',
        'created_at': now,
        'updated_at': now,
    }
    if encrypted_flag and cred_payload_b64:
        doc['encrypted'] = True
        doc['payload_b64'] = cred_payload_b64
        if cred_meta is not None:
            doc['meta'] = cred_meta
    else:
        doc['label'] = label
        doc['note'] = note
        if url_plain:
            doc['url'] = url_plain

    saved_files = []
    i = 0
    for file_key in request.files:
        f = request.files[file_key]
        if not f:
            continue
        filename = secure_filename(f.filename or f"upload_{i}")
        raw = f.read()
        content_type = getattr(f, 'content_type', None) or 'application/octet-stream'
        # If not client-encrypted, encrypt server-side before storing
        if not encrypted_flag:
            cipher_bytes, f_meta = encrypt_bytes(raw)
            data_bytes = cipher_bytes
        else:
            data_bytes = raw
            f_meta = None
        grid_id = fs.put(data_bytes, filename=filename, content_type=content_type, metadata={'owner_id': str(owner_id)})
        meta = None
        if enc_meta_list and i < len(enc_meta_list):
            meta = enc_meta_list[i]
        elif f_meta is not None:
            meta = f_meta
        saved_files.append({
            'gfs_id': grid_id,
            'filename': filename,
            'length': len(data_bytes),
            'content_type': content_type,
            'encrypted': bool(meta),
            'enc_meta': meta,
        })
        i += 1

    if saved_files:
        doc['files'] = saved_files

    res = db.vault_items.insert_one(doc)
    out = db.vault_items.find_one({'_id': res.inserted_id})
    out['_id'] = str(out['_id'])
    out['owner_id'] = str(out['owner_id'])
    return jsonify({'item': out}), 201


@vault_bp.route('/file/<file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    """Download a file attachment if it belongs to an item owned by the user."""
    try:
        fid = ObjectId(file_id)
    except Exception:
        return jsonify({'error': 'File not found'}), 404

    # Ensure referenced by a vault item owned by the user
    uid = _obj_id(current_user.get_id())
    linked = db.vault_items.find_one({'owner_id': uid, 'files.gfs_id': fid})
    if not linked:
        return jsonify({'error': 'File not found'}), 404

    try:
        gridout = fs.get(fid)
    except Exception:
        return jsonify({'error': 'File not found'}), 404

    data = gridout.read()
    # Check if this specific file entry is server-encrypted; if so, decrypt before sending
    try:
        f_entry = None
        for f in (linked.get('files') or []):
            try:
                if str(f.get('gfs_id')) == str(fid):
                    f_entry = f
                    break
            except Exception:
                continue
        if f_entry and f_entry.get('encrypted') and isinstance(f_entry.get('enc_meta'), dict) and f_entry['enc_meta'].get('server'):
            data = decrypt_bytes(data, f_entry['enc_meta'])
    except Exception:
        pass
    resp = send_file(
        io.BytesIO(data),
        mimetype=(getattr(gridout, 'content_type', None) or 'application/octet-stream'),
        as_attachment=True,
        download_name=(getattr(gridout, 'filename', None) or 'download'),
    )
    return resp


@vault_bp.route('/items/id/<item_id>', methods=['DELETE'])
@login_required
def delete_item(item_id):
    uid = _obj_id(current_user.get_id())
    iid = _obj_id(item_id)
    if not iid:
        return jsonify({'error': 'Invalid id'}), 400
    it = db.vault_items.find_one({'_id': iid, 'owner_id': uid})
    if not it:
        return jsonify({'error': 'Not found'}), 404

    # Delete associated GridFS files
    for f in (it.get('files') or []):
        try:
            fs.delete(ObjectId(f['gfs_id']))
        except Exception:
            pass

    db.vault_items.delete_one({'_id': iid})
    return '', 204


@vault_bp.route('/items/id/<item_id>/reveal', methods=['GET'])
@login_required
def reveal_item(item_id):
    """Reveal server-encrypted item contents for the owner."""
    uid = _obj_id(current_user.get_id())
    iid = _obj_id(item_id)
    if not iid:
        return jsonify({'error': 'Invalid id'}), 400
    it = db.vault_items.find_one({'_id': iid, 'owner_id': uid})
    if not it:
        return jsonify({'error': 'Not found'}), 404
    payload_b64 = it.get('payload_b64')
    meta = it.get('meta') or {}
    if not payload_b64 or not isinstance(meta, dict) or not meta.get('server'):
        return jsonify({'error': 'Not server-encrypted'}), 400
    try:
        obj = decrypt_json(payload_b64, meta)
    except Exception:
        return jsonify({'error': 'Decrypt failed'}), 400
    return jsonify({'payload': obj})


@vault_bp.route('/migrate/self', methods=['POST'])
@login_required
def migrate_self_plain_to_server_enc():
    """Migrate current user's plaintext items to server-side encryption.

    - For non-file items: move all known fields into an encrypted payload and remove plaintext fields.
    - For file items: encrypt GridFS bytes where files[].encrypted is false and attach enc_meta, mark encrypted.
    """
    uid = _obj_id(current_user.get_id())
    now = datetime.utcnow()
    # Non-file items without payload_b64
    plain_q = {'owner_id': uid, 'payload_b64': {'$exists': False}, 'type': {'$ne': 'file'}}
    updated = 0
    for it in db.vault_items.find(plain_q):
        try:
            payload = {k: v for k, v in it.items() if k not in ['_id','owner_id','created_at','updated_at','type','files']}
            payload['type'] = it.get('type') or 'password'
            ct_b64, meta = encrypt_json(payload)
            db.vault_items.update_one({'_id': it['_id']}, {'$set': {
                'encrypted': True,
                'payload_b64': ct_b64,
                'meta': meta,
                'updated_at': now,
            }, '$unset': {k: '' for k in payload if k not in ['type']}})
            updated += 1
        except Exception:
            continue

    # File items: encrypt underlying files if not encrypted
    files_q = {'owner_id': uid, 'type': 'file'}
    files_updated = 0
    for it in db.vault_items.find(files_q):
        files = it.get('files') or []
        new_files = []
        changed = False
        for f in files:
            try:
                if not f.get('encrypted'):
                    go = fs.get(ObjectId(str(f['gfs_id'])))
                    data = go.read()
                    cipher, meta = encrypt_bytes(data)
                    # Replace GridFS file with encrypted content
                    fs.delete(go._id)
                    new_id = fs.put(cipher, filename=go.filename, content_type=go.content_type, metadata={'owner_id': str(uid)})
                    f['gfs_id'] = new_id
                    f['encrypted'] = True
                    f['enc_meta'] = meta
                    f['length'] = len(cipher)
                    changed = True
                new_files.append(f)
            except Exception:
                new_files.append(f)
        if changed:
            db.vault_items.update_one({'_id': it['_id']}, {'$set': {'files': new_files, 'updated_at': now}})
            files_updated += 1

    return jsonify({'migrated_items': updated, 'migrated_files': files_updated})
