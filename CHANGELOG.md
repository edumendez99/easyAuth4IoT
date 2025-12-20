# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

