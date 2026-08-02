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
  - [TrustTab](#trusttab)
  - [NtpTab](#ntptab)
  - [AboutTab](#abouttab)
  - [ECDH Dialog](#ecdh-dialog)
- [Components](#components)
  - [RecoveryUnlockDialog](#recoveryunlockdialog)
  - [UpdateFriendKeysDialog](#updatefriendkeysdialog)
  - [TOTPVerifyDialog](#totpverifydialog)
  - [TOTPSetupDialog](#totpsetupdialog)
- [Supporting Views](#supporting-views)
  - [LockScreen](#lockscreen)
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
| `set_service_orchestrator(orchestrator)` | Store reference to ServiceOrchestrator for agent lifecycle |
| `start_queue_processing()` | Begin processing task queue on main thread + start crypto queue |
| `enqueue(func)` | Thread-safe task submission to UI queue |
| `start_ntp_sync(encryption_service, delay_ms=2000)` | Schedule deferred NTP sync |
| `register_hotkeys(lock_callback, unlock_callback)` | Register Ctrl+Shift+L/U hotkeys |
| `start_agents()` | Start all background agents via ServiceOrchestrator |
| `stop_agents()` | Stop all background agents |
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
AuthController(root, key_store: KeyStore, ui=None, totp_persistence=None)
```

The optional `ui` parameter accepts a UI callback object. If `None`, a default `_DefaultUI` instance is used that wraps `tkinter.messagebox` and `password_dialog`. This decouples the controller from direct tkinter dependencies, making it testable without a GUI.

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
| `request_recovery_unlock()` | `(bool, KeyStore, TOTPService)` | Recovery unlock using Shamir shares (no password needed) |

#### TOTP Management

| Method | Returns | Description |
|--------|---------|-------------|
| `load_totp_secret(totp_service, password, ks)` | `bool` | Load with multiple decryption strategies |
| `persist_totp_secret(secret_bytes, password)` | `None` | Encrypt and store TOTP secret |
| `init_totp(password)` | `None` | Load existing or generate new |
| `generate_new_totp(password)` | `None` | Generate and persist new secret |
| `regenerate_totp()` | `None` | Regenerate from setup dialog |
| `show_totp_setup()` | `None` | Show TOTP setup dialog |
| `is_totp_setup_complete()` | `bool` | Check DB flag |
| `set_totp_setup_complete(value)` | `None` | Set DB flag |
| `is_totp_enabled()` | `bool` | Check DB flag |
| `set_totp_enabled(value)` | `None` | Set DB flag |

#### Password & Duress

| Method | Returns | Description |
|--------|---------|-------------|
| `change_password()` | `bool` | Orchestrate password change |
| `set_duress_password()` | `bool` | Orchestrate duress setup |
| `enter_duress_mode(password=None)` | `None` | Load decoy state |
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

Creates: EncryptionService, FileService, FriendsService, ClipboardService, GlobalSecretService

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `encryption_service` | EncryptionService | Current instance |
| `file_service` | FileService | Current instance |
| `friends_service` | FriendsService | Current instance |
| `clipboard_service` | ClipboardService | Current instance |
| `global_secret_service` | GlobalSecretService | Current instance |
| `crypto_queue` | CryptoTaskQueue | Background crypto task queue |
| `service_lock` | RLock | Thread-safe service access |

#### Methods

| Method | Description |
|--------|-------------|
| `set_backup_agent(backup_service)` | Configure BackupReminderAgent with backup service |
| `rebuild_services(new_key_store, tab_references)` | Rebuild all services, update tab refs, publish event |
| `shutdown()` | Flush ratchet states, stop agents, clean up clipboard service |
| `start_agents()` | Start background agents (BackupReminderAgent, RatchetMaintenanceAgent, SystemMonitorAgent, KeyInspectorAgent) |
| `stop_agents()` | Stop all background agents |

#### Events Published
- `SERVICES_REBUILT`

---

## Views (Tabs)

13 view modules: about_tab, decrypt_tab, dialogs, ecdh, encrypt_tab, file_tab, friends_tab, help_tab, lock_screen, ntp_tab, secret_tab, trust_tab, utils.

### EnigmaApp (Main Window)

**File:** `app.py`

Main application window orchestrating header, tabs, lock screen, and event subscriptions.

#### Initialization Sequence

The startup sequence is delegated to **`builders/app_builder.py`** (`AppBuilder`), which runs 6 steps:

1. `step1_init_window` — Configure root window, style, and EventBus
2. `step2_init_database` — Detect first-run status, ensure DB schema exists
3. `step3_init_keystore` — Create `KeyStore` instance
4. `step4_init_controllers` — Create `ApplicationController`, `TotpPersistence`, `AuthController`; start task queue
5. `step5_authenticate` — Load keys (first-run setup or login), enforce mandatory TOTP setup, verify startup TOTP
6. `step6_init_services` — Create `ServiceOrchestrator` + `TrustChainService`, wire dependencies, start deferred NTP sync

After `build()` returns successfully, `EnigmaApp.__init__` continues with:
- Setup header and tabs
- Initialize lock screen
- Subscribe to event bus
- Register global hotkeys
- Start background agents

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

**File:** `views/encrypt_tab.py`

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
| `send_message()` | Validate, encrypt via CryptoTaskQueue, log result. Disables the Send button + shows a busy cursor while in flight; surfaces failures via `friendly_error` (the `crypto_queue` path reports through `on_error`). Bound to **Ctrl+Enter**; Escape clears. |
| `copy_last_sent()` | Copy last encrypted message to clipboard with inline button feedback (no modal) |
| `clear_input()` | Clear message input |
| `clear_log()` | Clear the sent-messages history (confirms first; no-op when already empty) |
| `notify_friend_list_changed()` | Refresh friend dropdown |
| `_update_friend_list()` | Fetch names from FriendsService |
| `_on_friend_changed(event)` | Auto-select encryption mode based on friend capabilities |

> The sent-messages log is **read-only** (toggled to editable only while inserting) so ciphertext history can't be accidentally corrupted.

#### Constants
- `MAX_MESSAGE_SIZE = 1 MB`

---

### DecryptTab

**File:** `views/decrypt_tab.py`

Message decryption interface with self-destruct awareness and ratchet mode indicator.

#### Constructor
```python
DecryptTab(parent, encryption_service, clipboard_service, task_queue, crypto_queue=None)
```

#### Methods

| Method | Description |
|--------|-------------|
| `receive_message()` | Decrypt via CryptoTaskQueue, show result with mode indicator. Disables the Decrypt button + busy cursor while running; failures shown via `friendly_error`. Bound to **Ctrl+Enter**. |
| `copy_decrypted()` | Copy the decrypted plaintext to the clipboard with inline button feedback |
| `paste_from_clipboard()` | Paste clipboard content (confirms before overwriting non-empty input) |
| `clear()` | Clear input, output, and indicators |
| `_show_decrypted(text, decrypt_mode)` | Display result (read-only, replaces previous) with PQC/Ratchet/Legacy indicator; the hybrid-signature indicator renders on its **own** label so it no longer hides the mode |

> The decrypted-message pane is **read-only**, and a static caption clarifies that self-destruct is best-effort (it depends on the sender's settings and the recipient's client).

---

### SecretTab

**File:** `views/secret_tab.py`

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

**File:** `views/file_tab.py`

File encryption/decryption with password, global secret, or friend's shared secret.

#### Constructor
```python
FileTab(parent, file_service, friends_service, global_secret_service, root, task_queue, crypto_queue=None)
```

#### Methods

| Method | Description |
|--------|-------------|
| `encrypt_file()` | Select method, encrypt off-thread; busy state on both action buttons; suggests no overwrite of the original |
| `decrypt_file()` | Auto-detect method, handle SharedSecretDetected; suggests an output filename (strips trailing `.enc`) |
| `refresh_list()` | Refresh friend dropdown |
| `_submit_file_task(do_work, on_success, on_error)` | Run a file crypto op via the queue or a thread fallback. The fallback catches **all** exceptions (not just `FileServiceError`) so no failure dies silently in a daemon thread |
| `_set_busy(busy)` | Disable both action buttons + toggle the busy cursor |
| `_handle_shared_detected(infile, outfile, detection)` | Confirm and decrypt with shared secret |
| `_prompt_password_and_decrypt(infile, outfile)` | Prompt for password and retry |

> Path length is validated against a platform-aware limit (260 on Windows, 4096 elsewhere) with a plain-language message. All user-facing errors use `friendly_error`.

---

### FriendsTab

**File:** `views/friends_tab.py`

Friend management with modern table UI, search, context menu, and detail panel.

#### Constructor
```python
FriendsTab(parent, friends_service, style_config=None, trust_chain_service=None)
```

#### UI Elements
- Action bar: Add, Remove, My Public Key, Set My Name, ECDH Exchange, PQC Exchange, Init Ratchet
- Search box with live filtering
- Treeview table with columns: Status, Name, RSA FP, ECDH, PQC, Hybrid Sig, Ratchet
- Detail panel with PEM display
- Right-click context menu

#### Methods

| Method | Description |
|--------|-------------|
| `refresh_list()` | Reload all friends from service (caches the result so filtering doesn't re-query the DB) |
| `filter_list()` | Apply search filter over the cached list |
| `add_friend_dialog()` | Full add friend form with PQC + hybrid sig fields |
| `remove_friend_dialog()` | Remove the **selected** friend after an `askyesno` confirmation (also bound to the `<Delete>` key); shows an info message if nothing is selected |
| `ecdh_with_selected()` | ECDH exchange with selected friend (key derivation runs off-thread via `run_busy`) |
| `show_my_pubkey()` | Display own public key and fingerprint |
| `init_ratchet_dialog()` | Initialize Double Ratchet (Alice/Bob role) |
| `reset_ratchet_dialog()` | Delete ratchet session |
| `set_my_name_dialog()` | Set display name for ratchet sender identity; persists via `KeyStore.set_my_name()` |
| `pqc_exchange_dialog()` | Multi-tab PQC key exchange dialog |
| `on_select(event)` | Update detail panel |

#### Events Published
- `FRIEND_LIST_CHANGED`, `FRIEND_ADDED`, `FRIEND_REMOVED`, `RATCHET_INITIALIZED`, `RATCHET_RESET`

> **UX notes:** an empty-state placeholder guides new users to "Add Friend" (and distinguishes "no matches" when filtering); ratchet init/reset and ECDH run off-thread with a busy cursor; row colors derive from the active theme (the text badge — "Secure"/"No Key" — is the primary, non-color-only signal); `<Double-1>`/`<Return>` open details.

---

### NtpTab

**File:** `views/ntp_tab.py`

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

### TrustTab

**File:** `views/trust_tab.py`

Trust chain certificate management interface with treeview, filters, and action buttons.

#### Constructor
```python
TrustTab(parent, trust_chain_service, friends_service, clipboard_service, key_store)
```

#### UI Elements
- Certificate treeview with columns: Subject, Type, Issuer, Status, Expires, Trust Level
- Filter: All / Valid / Revoked / Expired
- Actions: Issue Certificate, View Certificate, Revoke Certificate, Export, Import

#### Methods
| Method | Description |
|--------|-------------|
| `refresh_list()` | Reload certificates from service |
| `issue_certificate()` | Create and sign new certificate for a friend |
| `revoke_certificate()` | Mark selected certificate as revoked |
| `export_certificate()` | Export certificate to Base64 string |
| `import_certificate()` | Import certificate from Base64 string |
| `view_certificate_details()` | Show full certificate details dialog |

> **UX notes:** trust info is loaded once per refresh and cached, so the search box filters the cache instead of re-querying per keystroke; expired/revoked certificates render a distinct **text** status (not color/date alone); revoking a cert when a friend has more than one prompts the user to pick which (showing issuer/date/cert-id in the confirmation); the import dialog is resizable and modal.

---

### AboutTab

**File:** `views/about_tab.py`

Version info, backup export/import, password change, duress password setup.

#### Constructor
```python
AboutTab(parent, key_store, auth_controller, backup_service=None)
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

8 component dialogs total.

### AddFriendDialog
**File:** `components/add_friend_dialog.py` — Full form for adding friends with all key fields.

### PqcExchangeDialog
**File:** `components/pqc_exchange_dialog.py` — Multi-tab PQC key exchange (generate, import, status).

### HybridSigExchangeDialog
**File:** `components/hybrid_sig_exchange_dialog.py` — Multi-tab hybrid signature key exchange.

### CertificateDialog
**File:** `components/certificate_dialog.py` — View and manage trust certificates.

### KeyRecoveryDialog
**File:** `components/key_recovery_dialog.py` — Shamir secret sharing key recovery UI.

### RecoveryUnlockDialog
**File:** `components/recovery_unlock_dialog.py` (332 lines) — Recovery key reconstruction without master password; used from lock screen or startup login via `AuthController.request_recovery_unlock()`.

### UpdateFriendKeysDialog
**File:** `components/update_friend_keys_dialog.py` (391 lines) — Update RSA, ECDH, PQC, and hybrid signature keys for a friend; requires master password for authorization.

### TOTPVerifyDialog / TOTPSetupDialog
**File:** `components/totp_dialogs.py` — TOTP verification and setup dialogs.

---

## Supporting Views

### LockScreen

**File:** `views/lock_screen.py`

Full-window overlay blocking interaction when locked.

| Method | Description |
|--------|-------------|
| `lock()` | Show overlay with lock icon, unlock button, hotkey hint. Calls `grab_set()` so the overlay is **truly modal** (input can't reach widgets behind it); the grab is released around the unlock callback so the downstream password/TOTP dialog still works |
| `unlock()` | Release the grab and remove the overlay |
| `set_status(text)` | Update status text (e.g. "Incorrect password", "Locked out", "Unlocking…"); defaults to "🔒 LOCKED" |
| `is_locked` | Property: whether overlay is active |

> `<Escape>` is bound to a no-op so the lock can never be dismissed silently; the unlock shortcut hint is shown on all platforms (Cmd on macOS, Ctrl elsewhere).

### ECDH Dialog

**File:** `views/ecdh.py`

Modal dialog for X25519 ECDH key exchange with fingerprint verification.

```python
perform_ecdh(parent, purpose="friend") -> (derived_secret, friend_x25519_b64) | None
```

---

## Utility Functions

### Pure Utilities

**File:** `views/utils.py`

| Function | Returns | Description |
|----------|---------|-------------|
| `validate_password_strength(pw)` | `(is_valid, message, score)` | Military-grade password validation |
| `get_strength_label(score)` | `(label, color)` | Visual strength indicator |

### Shared UI Helpers

**File:** `views/utils.py`

Reusable helpers that standardize UX across all tabs and dialogs. Prefer these over ad-hoc implementations so behavior (error wording, busy state, modal hygiene) stays consistent.

| Function | Description |
|----------|-------------|
| `friendly_error(exc) -> str` | Map an exception to a safe, user-facing message. Use **instead of** `str(exc)` in `messagebox.showerror` for technical/unexpected errors. Maps common types (decryption, timeout, permission, base64/JSON/MAC failures); falls back to a generic message. Always log the raw detail separately with `logger.exception(...)`. |
| `init_modal(dlg, parent, focus_widget=None, on_close=None)` | Apply consistent modal hygiene to a `Toplevel`. Centers over `parent`, sets `transient` + `grab_set` (true modality), binds `<Escape>` and the window-close (X) button to `on_close` (defaults to `dlg.destroy`), and sets initial keyboard focus. Call **once** after the dialog is created and sized. Idempotent with existing `transient()`/`grab_set()` calls. |
| `center_over_parent(dlg, parent)` | Position a `Toplevel` centered over its parent (used internally by `init_modal`; can be called directly). |
| `run_busy(widget, work, on_done=None, on_error=None, busy_widgets=None)` | Run a blocking `work()` callable off the UI thread. Shows a `watch` cursor on the toplevel, disables `busy_widgets` (e.g. the trigger button), then dispatches `on_done(result)` / `on_error(exc)` back on the Tk main thread (restoring cursor + widget states first). If `on_error` is omitted, shows `friendly_error` in a dialog. **Tkinter is not thread-safe — `work` must perform NO Tk/UI calls; do all UI updates in `on_done`/`on_error`.** |
| `flash_widget_text(widget, text, revert_to, ms=1500)` | Briefly change a widget's text (e.g. a copy button → "Copied ✓") then revert. Lightweight inline feedback in place of a modal "copied" dialog. |

> **Note on `submit_crypto_task`:** the encrypt/decrypt/file tabs already offload work via `src/crypto_task_helper.submit_crypto_task` (CryptoTaskQueue or a thread fallback). Its `error_map` is honored only on the thread-fallback path — when a `crypto_queue` is present, surface errors in the task's `on_error` callback, not via `error_map`.

### Dialogs

**File:** `views/dialogs.py`

| Function | Returns | Description |
|----------|---------|-------------|
| `password_dialog(parent, title, confirm, topmost, bg, fg, enforce_strength)` | `SecureString \| None` | Modal password entry with strength meter |

### Password Requirements
- Minimum 16 characters
- Uppercase + lowercase + digit + special character
- Not in common passwords list
- No excessive repetition or sequential patterns

**File:** `main.py`

Application entry point. Configures logging, creates themed Tkinter window (`darkly` theme), handles PyInstaller DLL path resolution for liboqs, and runs anti-tamper checks before any other imports when running as a frozen .exe.


