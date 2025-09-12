import os
import json
import base64
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hmac

from .config import get_config


def _master_key_bytes() -> bytes:
    cfg = get_config()
    key = cfg.get('db_encryption_key') or ''
    if not key:
        raise RuntimeError('DB encryption key not configured')
    # Derive 32 bytes from provided secret (supports raw hex or any string)
    try:
        # If hex, normalize
        k = bytes.fromhex(key)
        if len(k) >= 16:
            return _hkdf_root(k)
    except Exception:
        pass
    # Fallback: hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key.encode('utf-8'))
    return digest.finalize()


def _hkdf_root(seed: bytes) -> bytes:
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'ea4i-root-salt-v1',
        info=b'ea4i-root-derive',
    )
    return hk.derive(seed)


def _derive_subkey(master: bytes, salt: bytes, info: bytes) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hk.derive(master)


def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode('ascii')


def _b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))


def encrypt_json(obj: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    master = _master_key_bytes()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    subkey = _derive_subkey(master, salt, b'ea4i-json-v1')
    aead = AESGCM(subkey)
    data = json.dumps(obj or {}, separators=(',', ':')).encode('utf-8')
    ct = aead.encrypt(nonce, data, None)
    meta = {
        'alg': 'AES-GCM',
        'kdf': 'HKDF-SHA256',
        'salt_b64': _b64(salt),
        'nonce_b64': _b64(nonce),
        'server': True,
        'ver': 1,
    }
    return _b64(ct), meta


def decrypt_json(payload_b64: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    if not payload_b64 or not meta:
        raise ValueError('missing payload/meta')
    master = _master_key_bytes()
    salt = _b64dec(meta.get('salt_b64') or '')
    nonce = _b64dec(meta.get('nonce_b64') or '')
    if not salt or not nonce:
        raise ValueError('invalid meta')
    subkey = _derive_subkey(master, salt, b'ea4i-json-v1')
    aead = AESGCM(subkey)
    pt = aead.decrypt(nonce, _b64dec(payload_b64), None)
    return json.loads(pt.decode('utf-8'))


def encrypt_bytes(buf: bytes) -> Tuple[bytes, Dict[str, Any]]:
    master = _master_key_bytes()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    subkey = _derive_subkey(master, salt, b'ea4i-bytes-v1')
    aead = AESGCM(subkey)
    ct = aead.encrypt(nonce, buf, None)
    meta = {
        'alg': 'AES-GCM',
        'kdf': 'HKDF-SHA256',
        'salt_b64': _b64(salt),
        'nonce_b64': _b64(nonce),
        'server': True,
        'ver': 1,
    }
    return ct, meta


def decrypt_bytes(ct: bytes, meta: Dict[str, Any]) -> bytes:
    master = _master_key_bytes()
    salt = _b64dec(meta.get('salt_b64') or '')
    nonce = _b64dec(meta.get('nonce_b64') or '')
    if not salt or not nonce:
        raise ValueError('invalid meta')
    subkey = _derive_subkey(master, salt, b'ea4i-bytes-v1')
    aead = AESGCM(subkey)
    return aead.decrypt(nonce, ct, None)


def hmac_tag(value: str, scope: str | bytes) -> str:
    """
    Returns a hex HMAC-SHA256 of the value scoped by device or owner id.
    Use for indexing (e.g., username) without storing plaintext.
    """
    if value is None:
        value = ''
    v = value.strip().lower().encode('utf-8')
    if isinstance(scope, str):
        s = scope.encode('utf-8')
    else:
        s = scope
    key = _master_key_bytes()
    return hmac.new(key, s + b'|' + v, digestmod='sha256').hexdigest()
