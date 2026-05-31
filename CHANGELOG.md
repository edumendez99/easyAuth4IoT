# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-05-31

### Added

#### Relationship Graph
- New interactive **Relationship Graph** module under `/graph` to visualize system entities and their connections (users, devices, credentials, files, and templates).
- Color-coded nodes with distinct shapes and letter badges for user roles, devices, credentials, files, and config templates.
- Features including full-text search, node type filtering, interactive zoom controls (zoom in, zoom out, reset, and fit to screen), and node click redirection to entity list pages.
- Access-controlled API endpoint (`/graph/api`) exposing nodes based on active user role/ownership.

#### Local Encryption Keychain (Llavero)
- Multi-seed local keychain replacing the single-seed local encryption input.
- Support for multiple BIP-39 seed phrases (both 12 and 24 words) with custom labels.
- Automated decryption fallback that sequentially tests all keychain seeds when decrypting client-side items.
- Session-persistent storage options to remember the keychain.

#### File Attachments & Config Files
- **Device File Attachments**: Added support for uploading, listing, downloading, and deleting files for individual devices (secured in GridFS).
- **Config Template Files**: Config templates dashboard now supports uploading, downloading, and deleting config-related files using GridFS.
- Added global 50 MB maximum upload size limit configuration (`MAX_CONTENT_LENGTH`).

#### Real-time Template Validation & Vault Enhancements
- Real-time linting/validation of JSON, XML, and YAML templates in the template editor (including server-side validation using PyYAML).
- Separated client-side decrypted and server-side revealed actions in Vault cards.
- Server-encrypted TOTP keys now display a live circular rotation progress timer (SVG radial ring indicator) showing remaining seconds in real-time.

### Technical

#### Backend
- Registered `/graph` blueprint in `app.py`.
- New `utils/graph.py` file with graph rendering endpoints.
- New endpoints in `utils/config_templates.py` for config template files management (`/api/files`, etc.).
- New endpoints in `utils/devices.py` for device file attachment uploads and downloads (`/<device_id>/files`, etc.).
- Added `MAX_CONTENT_LENGTH = 50 * 1024 * 1024` limit in `app.py`.

#### Frontend
- New relationship graph page: `templates/graph/view.html`.
- New relationship graph stylesheet & D3.js visualization script: `static/js/graph.js`.
- Updated `templates/base.html` with keychain modal and graph menu item.
- Updated `templates/vault/list.html` with server vs client decryption buttons, SVG circular TOTP progress rings, and Vue.js methods.
- Updated `templates/config_templates/list.html` to support file uploading/management and real-time syntax checking.
- Updated `templates/devices/credentials.html` to support file uploads/downloads and local decryption settings.

---

## [1.0.1] - 2024-12-19

### Added

#### Config Templates
- Brand-new **Config Templates** module to generate device configuration files.
- Support for multiple file types: JSON, XML, YAML, INI, CONF, ENV, SH, TXT.
- Dynamic placeholder system:
  - `{{ device.* }}` – Device fields (name, serial_number, barcode, manufacturer, etc.)
  - `{{ device.custom.* }}` – Device custom fields.
  - `{{ credential.* }}` – Credential fields (username, password, token, etc.)
- File-format validation per file type (JSON, XML, YAML).
- Template preview with sample data.
- Config generation selecting device and credential.
- Copy-to-clipboard and download actions for rendered files.

#### Device Custom Fields
- Devices now support **custom fields** (`custom_fields`).
- UI to add/edit/remove key-value pairs when creating or editing a device.
- Custom fields can be referenced inside templates via `{{ device.custom.field_name }}`.
- Automatic key sanitization (alphanumeric + underscore).

#### Maintenance & Event Timeline
- New **Timeline** tab on the device credentials page.
- Lifecycle event logging:
  - 🔧 Maintenance (battery replacement, sensor cleaning, etc.)
  - 📦 Firmware update
  - 🔄 Reboot
  - 📝 Notes
  - ⚙️ Custom events
- Full CRUD API for logs.
- Color-coded timeline UI.
- Event-type filtering.
- Complete history with date, author, and description.

### Fixed

#### Credentials
- Fixed the edit flow for server-encrypted credentials.
- “Edit” button now reveals server-encrypted credentials automatically without asking for the local passphrase.
- Proper distinction between local encryption (requires seed) and server-side encryption (automatic reveal).

#### Config Templates
- Fixed Jinja2 errors when showing placeholder examples in the UI.
- Proper escaping of `{{ }}` using `{% raw %}` blocks.
- Improved format validation to avoid saving malformed content.

#### UI/UX
- Enhanced color contrast on navigation tabs.
- Improved feedback when rendered content is empty.

### Technical

#### Backend
- New `config_templates` blueprint in `utils/config_templates.py`.
- New endpoints in `utils/devices.py`:
  - `GET /devices/<id>/logs` – List events.
  - `POST /devices/<id>/logs` – Create event.
  - `PUT /devices/<id>/logs/<log_id>` – Update event.
  - `DELETE /devices/<id>/logs/<log_id>` – Delete event.
- New MongoDB collection: `device_logs`.
- `custom_fields` attribute added to the device model.

#### Frontend
- New page: `templates/config_templates/list.html`.
- Updated: `templates/devices/credentials.html` (tabs, timeline).
- Updated: `templates/devices/list.html` (custom fields).

---

## [1.0.0] - 2024-12-XX

### Added
- Initial system release.
- User management (admin, staff, user).
- IoT device management.
- Credentials system with local and server-side encryption.
- Secure vault for secrets.

