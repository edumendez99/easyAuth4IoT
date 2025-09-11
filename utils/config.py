import os
from typing import Dict, Any

_cfg_cache: Dict[str, Any] | None = None


def _project_root() -> str:
    # utils/ -> project root
    return os.path.dirname(os.path.dirname(__file__))


def _parse_bool(val: str) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def _parse_int(val: str, default: int | None = None) -> int | None:
    try:
        return int(str(val).strip())
    except Exception:
        return default


def _load_env_file() -> Dict[str, str]:
    path = os.path.join(_project_root(), 'env.txt')
    out: Dict[str, str] = {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    k, v = line.split('=', 1)
                    out[k.strip()] = v.strip()
    except Exception:
        pass
    return out


def get_config() -> Dict[str, Any]:
    global _cfg_cache
    if _cfg_cache is not None:
        return _cfg_cache

    raw = _load_env_file()

    # Mongo settings
    mongo_uri = raw.get('mongo_uri') or None
    mongo_host = raw.get('mongo_host') or raw.get('mongodb_host') or 'localhost'
    mongo_port = _parse_int(raw.get('mongo_port') or raw.get('mongodb_port') or '27017', 27017)
    mongo_db = raw.get('mongo_db') or raw.get('mongodb_db') or 'easyAuth4IoT'

    if not mongo_uri:
        mongo_uri = f"mongodb://{mongo_host}:{mongo_port}/"

    # Server
    server_port = _parse_int(raw.get('server_port') or raw.get('port') or '5000', 5000)
    server_host = (raw.get('server_host') or raw.get('host') or '0.0.0.0').strip()

    # UI colors
    ui_primary = raw.get('ui_primary') or raw.get('primary_color') or '#005349'
    ui_secondary = raw.get('ui_secondary') or raw.get('secondary_color') or '#009f8c'

    # Secret keys
    secret_key = raw.get('secret_key') or raw.get('flask_secret') or 'your-secret-key'
    db_encryption_key = raw.get('db_encryption_key') or raw.get('database_encryption_key') or ''

    # Flags
    debug_mode = _parse_bool(raw.get('debugMode') or raw.get('debug') or 'false')

    _cfg_cache = {
        'raw': raw,
        'mongo_uri': mongo_uri,
        'mongo_host': mongo_host,
        'mongo_port': mongo_port,
        'mongo_db': mongo_db,
        'server_port': server_port,
        'server_host': server_host,
        'ui_primary': ui_primary,
        'ui_secondary': ui_secondary,
        'secret_key': secret_key,
        'db_encryption_key': db_encryption_key,
        'debug_mode': debug_mode,
    }
    return _cfg_cache
