from werkzeug.security import generate_password_hash
from datetime import datetime
from utils.database import db

def init_db():
    # Check if database already has data (only relevant collections)
    existing_users = db.users.count_documents({})
    existing_devices = db.devices.count_documents({})
    existing_logins = db.device_logins.count_documents({})
    
    print(f"Current database state: {existing_users} users, {existing_devices} devices, {existing_logins} device logins")
    print("Adding example data without erasing existing records...")
    
    # Create helpful indexes (safe: catch duplicates on unique)
    def ensure_indexes():
        def safe_create(coll, fields, unique=False, name=None, sparse=False):
            try:
                spec = fields if isinstance(fields, list) else [(fields, 1)]
                db[coll].create_index(spec, unique=unique, name=name, sparse=sparse)
                print(f"Index ensured on {coll}: {name or spec}")
            except Exception as e:
                print(f"Index creation failed for {coll} ({name or fields}): {e}")

        # Users
        safe_create('users', [('username', 1)], unique=True, name='u_username')
        safe_create('users', [('email', 1)], unique=True, name='u_email', sparse=True)

        # Devices
        safe_create('devices', [('created_by', 1)], name='i_devices_created_by')
        safe_create('devices', [('assigned_to', 1)], name='i_devices_assigned_to', sparse=True)
        safe_create('devices', [('assigned_users', 1)], name='i_devices_assigned_users', sparse=True)
        safe_create('devices', [('owner_id', 1)], name='i_devices_owner_id', sparse=True)
        safe_create('devices', [('created_at', -1)], name='i_devices_created_at')

        # Device logins
        safe_create('device_logins', [('device_id', 1)], name='i_logins_device')
        safe_create('device_logins', [('username', 1)], name='i_logins_username')
        # New index for server-side encrypted username tag
        safe_create('device_logins', [('tag_username', 1)], name='i_logins_tag_username', sparse=True)
        # Migrate legacy unique index to a partial unique index only for userpass credentials
        try:
            db.device_logins.drop_index('u_logins_device_username')
            print('Dropped legacy index: u_logins_device_username')
        except Exception as e:
            print(f'Legacy index not dropped (may not exist): {e}')
        try:
            db.device_logins.create_index(
                [('device_id', 1), ('username', 1)],
                unique=True,
                name='u_logins_device_username_userpass',
                partialFilterExpression={'type': 'userpass', 'username': {'$type': 'string'}}
            )
            print('Index ensured on device_logins: u_logins_device_username_userpass (partial unique)')
        except Exception as e:
            print(f'Index creation failed for device_logins (partial userpass): {e}')
        # Unique constraint for server-encrypted userpass using tag_username
        try:
            db.device_logins.create_index(
                [('device_id', 1), ('tag_username', 1)],
                unique=True,
                name='u_logins_device_tag_userpass',
                partialFilterExpression={'type': 'userpass', 'tag_username': {'$exists': True}}
            )
            print('Index ensured on device_logins: u_logins_device_tag_userpass (partial unique)')
        except Exception as e:
            print(f'Index creation failed for device_logins (tag unique): {e}')

    def backfill_device_logins_types():
        try:
            # Set type for certificate docs first (if any)
            res1 = db.device_logins.update_many(
                {'files': {'$exists': True}, '$or': [{'type': {'$exists': False}}, {'type': None}]},
                {'$set': {'type': 'certificate'}}
            )
            # Then tokens
            res2 = db.device_logins.update_many(
                {'token': {'$exists': True}, '$or': [{'type': {'$exists': False}}, {'type': None}]},
                {'$set': {'type': 'token'}}
            )
            # Finally userpass (any doc with username and missing type)
            res3 = db.device_logins.update_many(
                {'username': {'$exists': True}, '$or': [{'type': {'$exists': False}}, {'type': None}]},
                {'$set': {'type': 'userpass'}}
            )
            print(f"Backfill device_logins types: cert={res1.modified_count}, token={res2.modified_count}, userpass={res3.modified_count}")
        except Exception as e:
            print(f"Backfill device_logins types failed: {e}")

    backfill_device_logins_types()
    ensure_indexes()
    
    # Create example users
    users = [
        {
            'username': 'admin',
            'email': 'admin@easyAuth4IoT.com',
            'password': generate_password_hash('admin123'),
            'role': 'admin',
            'created_at': datetime.utcnow(),
            'is_active': True,
            'local_key': False
        },
        {
            'username': 'staff',
            'email': 'staff@easyAuth4IoT.com',
            'password': generate_password_hash('staff123'),
            'role': 'staff',
            'created_at': datetime.utcnow(),
            'is_active': True,
            'local_key': False
        },
        {
            'username': 'user1',
            'email': 'user1@easyAuth4IoT.com',
            'password': generate_password_hash('user123'),
            'role': 'user',
            'created_at': datetime.utcnow(),
            'is_active': True,
            'local_key': False
        },
        {
            'username': 'user2',
            'email': 'user2@easyAuth4IoT.com',
            'password': generate_password_hash('user123'),
            'role': 'user',
            'created_at': datetime.utcnow(),
            'is_active': True,
            'local_key': False
        }
    ]
    
    # Check for existing users and only insert new ones
    new_users = []
    for user in users:
        if db.users.find_one({'username': user['username']}) is None:
            new_users.append(user)
    
    if new_users:
        user_insert_result = db.users.insert_many(new_users)
        print(f"Added {len(new_users)} new users")
    else:
        print("No new users added - all example users already exist")
    
    print("Database initialized with example users:")
    print("1. Admin user:")
    print("   - Username: admin")
    print("   - Password: admin123")
    print("2. Staff user:")
    print("   - Username: staff")
    print("   - Password: staff123")
    print("3. Regular users:")
    print("   - Username: user1")
    print("   - Username: user2")
    print("   - Password for both: user123")

    # Seed example devices (idempotent)
    try:
        admin = db.users.find_one({'username': 'admin'})
        staff = db.users.find_one({'username': 'staff'})
        user1 = db.users.find_one({'username': 'user1'})
        now = datetime.utcnow()
        sample_devices = [
            {
                'name': 'Sensor A',
                'description': 'Ejemplo de sensor asignado a user1',
                'created_at': now,
                'updated_at': now,
                'created_by': str(admin['_id'] if admin else ''),
                'updated_by': str(admin['_id'] if admin else ''),
                'owner_id': staff['_id'] if staff else None,
                'assigned_to': user1['_id'] if user1 else None,  # compat
                'assigned_users': [user1['_id']] if user1 else [],
            },
            {
                'name': 'Gateway X',
                'description': 'Ejemplo de gateway sin asignar',
                'created_at': now,
                'updated_at': now,
                'created_by': str(staff['_id'] if staff else (admin['_id'] if admin else '')),
                'updated_by': str(staff['_id'] if staff else (admin['_id'] if admin else '')),
                'owner_id': staff['_id'] if staff else None,
                'assigned_to': None,
                'assigned_users': [],
            },
        ]
        added = 0
        for d in sample_devices:
            exists = db.devices.find_one({'name': d['name']})
            if not exists:
                db.devices.insert_one(d)
                added += 1
            else:
                # Ensure existing sample devices are updated with new fields
                db.devices.update_one({'_id': exists['_id']}, {'$set': {
                    'owner_id': d.get('owner_id'),
                    'assigned_users': d.get('assigned_users', []),
                }})
        print(f"Added {added} sample devices")
    except Exception as e:
        print(f"Warning: could not seed devices: {e}")

    # Done (users + devices + device_logins indexes only)
    return

if __name__ == '__main__':
    init_db()
