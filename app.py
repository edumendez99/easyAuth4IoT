from flask import Flask, render_template, jsonify, request, url_for
from flask_babel import Babel, _
from flask.json.provider import JSONProvider
from flask_login import LoginManager, login_required, current_user
from flask_cors import CORS
from flasgger import Swagger
from utils.database import db
from utils.config import get_config
from utils.models import User
from utils.auth import auth_bp
from utils.users import user_bp
from utils.devices import devices_bp
from utils.vault import vault_bp
from utils.config_templates import config_templates_bp
from utils.filters import init_filters
from bson import ObjectId
from datetime import datetime
import json
import os

# Custom JSON provider to handle MongoDB ObjectId and datetime objects
class MongoJSONProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return json.dumps(obj, **kwargs, default=self._default)
    
    def loads(self, s, **kwargs):
        return json.loads(s, **kwargs)
    
    def _default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

app = Flask(__name__)
# Load configuration from env.txt
CFG = get_config()
app.config['SECRET_KEY'] = CFG.get('secret_key') or 'your-secret-key'  # Do NOT hardcode in production
app.config['BABEL_DEFAULT_LOCALE'] = 'es'  # Default language
app.config['DEBUG_MODE'] = bool(CFG.get('debug_mode'))
app.config['DB_ENCRYPTION_KEY'] = CFG.get('db_encryption_key') or ''
app.config['UI_PRIMARY'] = CFG.get('ui_primary') or '#005349'
app.config['UI_SECONDARY'] = CFG.get('ui_secondary') or '#009f8c'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max upload
app.json = MongoJSONProvider(app)
CORS(app)


# Initialize Swagger (Flasgger) for API documentation at /apidocs
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "Frizit API",
        "version": "1.0.0",
        "description": "API documentation for Frizit endpoints"
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Bearer token. Example: Bearer <token>"
        }
    },
    "security": [
        {"BearerAuth": []}
    ]
})

# Initialize Flask-Babel
babel = Babel(app)

# Inject _ into templates
def _static_file_exists(rel_path: str) -> bool:
    try:
        return os.path.isfile(os.path.join(app.root_path, 'static', rel_path))
    except Exception:
        return False


@app.context_processor
def inject_global():
    # Canonical brand asset names
    icon_rel = 'images/app_icon.png'
    logo_rel = 'images/app_logo.png'
    try:
        brand_icon_url = url_for('static', filename=icon_rel) if _static_file_exists(icon_rel) else None
    except Exception:
        brand_icon_url = None
    try:
        brand_logo_url = url_for('static', filename=logo_rel) if _static_file_exists(logo_rel) else None
    except Exception:
        brand_logo_url = None
    return dict(
        _=_ ,
        debug_mode=app.config.get('DEBUG_MODE', False),
        ui_primary=app.config.get('UI_PRIMARY', '#005349'),
        ui_secondary=app.config.get('UI_SECONDARY', '#009f8c'),
        brand_icon_url=brand_icon_url,
        brand_logo_url=brand_logo_url,
    )


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login_page'

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

# Register blueprints (core only)
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(user_bp, url_prefix='/users')
app.register_blueprint(devices_bp, url_prefix='/devices')
app.register_blueprint(vault_bp, url_prefix='/vault')
app.register_blueprint(config_templates_bp, url_prefix='/config-templates')

from utils.graph import graph_bp
app.register_blueprint(graph_bp, url_prefix='/graph')

# Initialize custom template filters
init_filters(app)

# Note: Indexes for users/devices/device_logins are created in init_db.py



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/home/kpis', methods=['GET'])
@login_required
def home_kpis():
    from utils.database import db
    # Only available for authenticated users
    if not current_user.is_authenticated:
        return jsonify({'error': 'unauthorized'}), 401

    uid = ObjectId(current_user.get_id())
    # Vault counts
    def ctyp(t):
        try:
            return db.vault_items.count_documents({'owner_id': uid, 'type': t})
        except Exception:
            return 0
    passwords = ctyp('password')
    tokens = ctyp('token')
    files = ctyp('file')
    # Last vault update
    try:
        last_v = db.vault_items.find({'owner_id': uid}).sort('updated_at', -1).limit(1)
        last_vault_update = None
        for x in last_v:
            lv = x.get('updated_at') or x.get('created_at')
            last_vault_update = lv.isoformat() if isinstance(lv, datetime) else None
            break
    except Exception:
        last_vault_update = None

    # Devices in role scope
    role = getattr(current_user, 'role', None)
    if role == 'admin':
        dev_q = {}
    elif role == 'staff':
        dev_q = {'owner_id': uid}
    else:
        dev_q = {'$or': [
            {'assigned_users': uid},
            {'assigned_to': uid}
        ]}
    try:
        devices_count = db.devices.count_documents(dev_q)
    except Exception:
        devices_count = 0
    try:
        last_d = db.devices.find(dev_q).sort('updated_at', -1).limit(1)
        last_device_update = None
        for d in last_d:
            ld = d.get('updated_at') or d.get('created_at')
            last_device_update = ld.isoformat() if isinstance(ld, datetime) else None
            break
    except Exception:
        last_device_update = None

    return jsonify({
        'passwords': passwords,
        'tokens': tokens,
        'files': files,
        'devices': devices_count,
        'last_vault_update': last_vault_update,
        'last_device_update': last_device_update,
        'requires_local_key': bool(getattr(current_user, 'local_key', False)),
    })

@app.route('/health')
def health():
    return {"status": "ok"}

if __name__ == '__main__':
    host = CFG.get('server_host') or '0.0.0.0'
    port = int(CFG.get('server_port') or 5000)
    debug_mode = app.config.get('DEBUG_MODE', False)
    
    if debug_mode:
        # Enable template auto-reload in debug mode
        app.config['TEMPLATES_AUTO_RELOAD'] = True
        app.jinja_env.auto_reload = True
        print(f"🔄 Live reload enabled - watching templates for changes")
    
    app.run(debug=debug_mode, host=host, port=port, use_reloader=debug_mode, extra_files=None)