# Views & Controllers Reference

Comprehensive documentation for all UI views (tabs) and MVC controllers.

---

## Table of Contents

- [Controllers](#controllers)
  - [ApplicationController](#applicationcontroller)
  - [AuthController](#authcontroller)
  - [ServiceOrchestrator](#serviceorchestrator)
- [Views (Tabs)](#views-tabs)
  - [EnigmaApp (Main Window)](#enigmaapp-main-window)
  - [EncryptTab](#encrypttab)
  - [DecryptTab](#decrypttab)
  - [SecretTab](#secrettab)
  - [FileTab](#filetab)
  - [FriendsTab](#friendstab)
  - [NtpTab](#ntptab)
  - [AboutTab](#abouttab)
- [Components](#components)
  - [TOTPVerifyDialog](#totpverifydialog)
  - [TOTPSetupDialog](#totpsetupdialog)
- [Supporting Views](#supporting-views)
  - [LockScreen](#lockscreen)
  - [VisualEnigma](#visualenigma)
  - [ECDH Dialog](#ecdh-dialog)
- [Utility Functions](#utility-functions)

---

## Controllers

### ApplicationController

**File:** `controllers/application_controller.py`

Manages application lifecycle, NTP synchronization, global hotkeys, and task queues.

#### Constructor
```python
ApplicationController(root)
```

Creates `CryptoTaskQueue`, initializes task queue for UI thread marshalling.

#### Methods

| Method | Description |
|--------|-------------|
| `start_queue_processing()` | Begin processing task queue on main thread + start crypto queue |
| `enqueue(func)` | Thread-safe task submission to UI queue |
| `start_ntp_sync(encryption_service, service_lock, delay_ms=2000)` | Schedule deferred NTP sync |
| `register_hotkeys(lock_callback, unlock_callback)` | Register Ctrl+Shift+L/U hotkeys |
| `shutdown()` | Clean up crypto queue, hotkeys, timeout executor |

#### Events Published
- `NTP_SYNCED` – after successful sync (includes `offset_ms`)
- `NTP_SYNC_FAILED` – when all servers fail

---

### AuthController

**File:** `controllers/auth_controller.py`

Coordinates login, unlock, TOTP verification, password management, and duress mode.

#### Constructor
```python
AuthController(root, key_store: KeyStore)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `master_password_hash` | `str` | Argon2 hash of master password |

#### Startup Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `load_keys(first_run)` | `bool` | Handle initial key loading |
| `enforce_mandatory_totp_setup()` | `bool` | Force TOTP setup if incomplete |
| `verify_startup_totp()` | `bool` | Verify TOTP on startup |

#### Unlock Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `request_unlock(current_ks)` | `(bool, KeyStore, TOTPService)` | Full unlock sequence |

#### TOTP Management

| Method | Description |
|--------|-------------|
| `load_totp_secret(totp_service, password, ks)` | Load with multiple decryption strategies |
| `persist_totp_secret(secret_bytes, password)` | Encrypt and store TOTP secret |
| `init_totp(password)` | Load existing or generate new |
| `generate_new_totp(password)` | Generate and persist new secret |
| `regenerate_totp()` | Regenerate from setup dialog |
| `show_totp_setup()` | Show TOTP setup dialog |
| `is_totp_setup_complete()` | Check DB flag |
| `set_totp_setup_complete(value)` | Set DB flag |
| `is_totp_enabled()` | Check DB flag |
| `set_totp_enabled(value)` | Set DB flag |

#### Password & Duress

| Method | Returns | Description |
|--------|---------|-------------|
| `change_password()` | `bool` | Orchestrate password change |
| `set_duress_password()` | `bool` | Orchestrate duress setup |
| `enter_duress_mode()` | `None` | Load decoy state |
| `wipe_sensitive_data()` | `None` | Clear all sensitive data |

#### Events Published
- `KEYS_LOADED`, `PASSWORD_CHANGED`, `TOTP_SETUP_COMPLETE`, `TOTP_VERIFIED`, `TOTP_CHANGED`, `DURESS_MODE_ENTERED`, `KEYS_WIPED`

---

### ServiceOrchestrator

**File:** `controllers/service_orchestrator.py`

Centralized manager for all business service instances. Handles creation, rebuilding, and dependency injection.

#### Constructor
```python
ServiceOrchestrator(root, key_store, crypto_queue=None)
```

Creates: `EncryptionService`, `FileService`, `FriendsService`, `ClipboardService`, `GlobalSecretService`

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `encryption_service` | EncryptionService | Current instance |
| `file_service` | FileService | Current instance |
| `friends_service` | FriendsService | Current instance |
| `clipboard_service` | ClipboardService | Current instance |
| `global_secret_service` | GlobalSecretService | Current instance |
| `service_lock` | RLock | Thread-safe service access |

#### Methods

| Method | Description |
|--------|-------------|
| `rebuild_services(new_key_store, tab_references)` | Rebuild all services, update tab refs, publish event |
| `shutdown()` | Clean up clipboard service |

#### Events Published
- `SERVICES_REBUILT`

---

## Views (Tabs)

### EnigmaApp (Main Window)

**File:** `app.py`

Main application window orchestrating header, tabs, lock screen, and event subscriptions.

#### Initialization Sequence
1. Configure EventBus with Tkinter root
2. Check first-run status
3. Initialize KeyStore
4. Initialize Controllers (Application, Auth, ServiceOrchestrator)
5. Start task queue processing
6. Load keys (first-run setup or existing login)
7. Enforce mandatory TOTP setup
8. Verify startup TOTP
9. Start deferred NTP sync
10. Setup header and tabs
11. Initialize lock screen
12. Subscribe to events
13. Register global hotkeys

#### Key Methods

| Method | Description |
|--------|-------------|
| `on_close()` | Shutdown services, wipe keys, publish APP_SHUTDOWN |
| `_emergency_lock()` | Wipe keys, lock screen, publish EMERGENCY_LOCK |
| `_request_unlock()` | Coordinate unlock via AuthController + ServiceOrchestrator |
| `_setup_event_subscriptions()` | Register FRIEND_LIST_CHANGED and SERVICES_REBUILT handlers |
| `_on_tab_changed(event)` | Auto-refresh content on tab switch |

---

### EncryptTab

**File:** `encrypt_tab.py`

Message encryption interface with friend selection, mode selection, signing, and self-destruct.

#### Constructor
```python
EncryptTab(parent, encryption_service, friends_service, clipboard_service, crypto_queue=None)
```

#### UI Elements
- Sign checkbox, Friend combo, Mode combo (Shared/RSA/PQC), Self-destruct toggle + duration
- Message input, Sent messages log
- Encrypt & Send, Clear, Copy Last Sent buttons

#### Methods

| Method | Description |
|--------|-------------|
| `send_message()` | Validate, encrypt via CryptoTaskQueue, log result |
| `copy_last_sent()` | Copy last encrypted message to clipboard |
| `clear_input()` | Clear message input |
| `notify_friend_list_changed()` | Refresh friend dropdown |
| `_update_friend_list()` | Fetch names from FriendsService |
| `_on_friend_changed(event)` | Auto-select encryption mode based on friend capabilities |

#### Constants
- `MAX_MESSAGE_SIZE = 1 MB`

---

### DecryptTab

**File:** `decrypt_tab.py`

Message decryption interface with self-destruct awareness and ratchet mode indicator.

#### Constructor
```python
DecryptTab(parent, encryption_service, clipboard_service, task_queue, crypto_queue=None)
```

#### Methods

| Method | Description |
|--------|-------------|
| `receive_message()` | Decrypt via CryptoTaskQueue, show result with mode indicator |
| `paste_from_clipboard()` | Paste clipboard content |
| `clear()` | Clear input and output |
| `_show_decrypted(text, decrypt_mode)` | Display result with PQC/Ratchet/Legacy indicator |

---

### SecretTab

**File:** `secret_tab.py`

Global shared secret management and ECDH key exchange.

#### Constructor
```python
SecretTab(parent, global_secret_service, clipboard_service)
```

#### Methods

| Method | Description |
|--------|-------------|
| `export_global()` | Copy Base64 secret to clipboard |
| `import_global()` | Import and replace global secret |
| `start_ecdh()` | Perform ECDH exchange for global secret |

---

### FileTab

**File:** `file_tab.py`

File encryption/decryption with password, global secret, or friend's shared secret.

#### Constructor
```python
FileTab(parent, file_service, friends_service, global_secret_service, root, task_queue, crypto_queue=None)
```

#### Methods

| Method | Description |
|--------|-------------|
| `encrypt_file()` | Select method, encrypt via CryptoTaskQueue |
| `decrypt_file()` | Auto-detect method, handle SharedSecretDetected |
| `refresh_list()` | Refresh friend dropdown |
| `_handle_shared_detected(infile, outfile, detection)` | Confirm and decrypt with shared secret |
| `_prompt_password_and_decrypt(infile, outfile)` | Prompt for password and retry |

---

### FriendsTab

**File:** `friends_tab.py`

Friend management with modern table UI, search, context menu, and detail panel.

#### Constructor
```python
FriendsTab(parent, friends_service, style_config=None)
```

#### UI Elements
- Action bar: Add, Remove, My Public Key, ECDH Exchange, PQC Exchange, Init Ratchet
- Search box with live filtering
- Treeview table with columns: Status, Name, RSA FP, ECDH, PQC, Hybrid Sig, Ratchet
- Detail panel with PEM display
- Right-click context menu

#### Methods

| Method | Description |
|--------|-------------|
| `refresh_list()` | Reload all friends from service |
| `filter_list()` | Apply search filter |
| `add_friend_dialog()` | Full add friend form with PQC + hybrid sig fields |
| `remove_friend_dialog()` | Remove selected friend |
| `ecdh_with_selected()` | ECDH exchange with selected friend |
| `show_my_pubkey()` | Display own public key and fingerprint |
| `init_ratchet_dialog()` | Initialize Double Ratchet (Alice/Bob role) |
| `reset_ratchet_dialog()` | Delete ratchet session |
| `pqc_exchange_dialog()` | Multi-tab PQC key exchange dialog |
| `on_select(event)` | Update detail panel |

#### Events Published
- `FRIEND_LIST_CHANGED`, `FRIEND_ADDED`, `FRIEND_REMOVED`, `RATCHET_INITIALIZED`, `RATCHET_RESET`

---

### NtpTab

**File:** `ntp_tab.py`

NTP synchronization status and manual sync with server selection.

#### Constructor
```python
NtpTab(parent, encryption_service)
```

#### Features
- Live local time display (1-second refresh)
- NTP time, offset, last sync display
- Preset server dropdown + custom server entry
- Automatic fallback through all known servers
- Updates EncryptionService with NTP time

---

### AboutTab

**File:** `about_tab.py`

Version info, backup export/import, password change, duress password setup.

#### Constructor
```python
AboutTab(parent, key_store, auth_controller)
```

#### Methods

| Method | Description |
|--------|-------------|
| `_export_backup()` | Export encrypted backup to file |
| `_import_backup()` | Import and restore from backup file |
| `_change_password()` | Delegate to AuthController |
| `_set_duress_password()` | Delegate to AuthController |

---

## Components

### TOTPVerifyDialog

**File:** `components/totp_dialogs.py`

Modal dialog for verifying a 6-digit TOTP code with countdown timer.

```python
TOTPVerifyDialog(parent, totp_service)
dialog.show() -> bool  # True if verified
```

### TOTPSetupDialog

**File:** `components/totp_dialogs.py`

Modal dialog for TOTP setup with QR code, provisioning URI, Base32 secret, live code preview, and regenerate button.

```python
TOTPSetupDialog(parent, totp_service, provisioning_uri, on_regenerate=None)
dialog.show() -> bool  # True if acknowledged
```

---

## Supporting Views

### LockScreen

**File:** `lock_screen.py`

Full-window overlay blocking interaction when locked.

| Method | Description |
|--------|-------------|
| `lock()` | Show overlay with lock icon, unlock button, hotkey hint |
| `unlock()` | Remove overlay |
| `set_status(text)` | Update status text |
| `is_locked` | Property: whether overlay is active |

### VisualEnigma

**File:** `visual_enigma.py`

Compact rotor animation for the header canvas.

| Method | Description |
|--------|-------------|
| `draw_compact(canvas, positions)` | Draw three rotating Enigma rotors |

### ECDH Dialog

**File:** `ecdh.py`

Modal dialog for X25519 ECDH key exchange with fingerprint verification.

```python
perform_ecdh(parent, purpose="friend") -> (derived_secret, friend_x25519_b64) | None
```

---

## Utility Functions

**File:** `utils.py`

| Function | Returns | Description |
|----------|---------|-------------|
| `validate_password_strength(pw)` | `(is_valid, message, score)` | Military-grade password validation |
| `get_strength_label(score)` | `(label, color)` | Visual strength indicator |
| `password_dialog(parent, title, confirm, topmost, bg, fg, enforce_strength)` | `SecureString \| None` | Modal password entry with strength meter |

### Password Requirements
- Minimum 16 characters
- Uppercase + lowercase + digit + special character
- Not in common passwords list
- No excessive repetition or sequential patterns

**File:** `main.py`

Application entry point. Configures logging, creates themed Tkinter window (`darkly` theme), handles PyInstaller DLL path resolution for liboqs.
