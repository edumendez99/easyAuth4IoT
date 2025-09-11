from pymongo import MongoClient
from bson.objectid import ObjectId
import gridfs

try:
    from .config import get_config
    _cfg = get_config()
    _MONGO_URI = _cfg.get('mongo_uri') or 'mongodb://localhost:27017/'
    _DB_NAME = _cfg.get('mongo_db') or 'easyAuth4IoT'
except Exception:
    _MONGO_URI = 'mongodb://localhost:27017/'
    _DB_NAME = 'easyAuth4IoT'

client = MongoClient(_MONGO_URI)
db = client[_DB_NAME]
# GridFS bucket for large binary data (e.g., certificates/keys)
fs = gridfs.GridFS(db)