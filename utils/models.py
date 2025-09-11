from flask_login import UserMixin
from bson import ObjectId

class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data
        
    def get_id(self):
        return str(self.user_data.get('_id'))
        
    @property
    def is_active(self):
        return True
        
    @property
    def is_authenticated(self):
        return True
        
    @property
    def is_anonymous(self):
        return False
        
    @property
    def role(self):
        return self.user_data.get('role', 'user')
        
    @property
    def username(self):
        return self.user_data.get('username')
        
    @property
    def email(self):
        return self.user_data.get('email')
    
    @property
    def local_key(self):
        return bool(self.user_data.get('local_key', False))
        
    def to_dict(self):
        return {
            'id': str(self.user_data.get('_id')),
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'local_key': self.local_key
        }
