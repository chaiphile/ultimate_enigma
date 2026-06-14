import json
import logging
from contextlib import closing

import database
from key_manager import KeyStore

logger = logging.getLogger(__name__)

TOTP_SECRET_KEY = "totp_secret_encrypted"
TOTP_SETUP_KEY = "totp_setup_complete"
TOTP_ENABLED_KEY = "totp_enabled"


class TotpPersistence:
    def __init__(self, key_store: KeyStore):
        self._ks = key_store

    @property
    def ks(self):
        return self._ks

    @ks.setter
    def ks(self, value):
        self._ks = value

    def load_totp_secret(self, totp_service, password=None, ks=None):
        if ks is None:
            ks = self._ks

        with closing(database.get_connection()) as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key=?", (TOTP_SECRET_KEY,)
            ).fetchone()

        if row:
            enc_dict = json.loads(row[0])

            if password:
                try:
                    totp_secret = database.decrypt_secret(enc_dict, password)
                    if len(totp_secret) == 20:
                        totp_service.set_raw_secret(totp_secret)
                    else:
                        totp_service.set_secret(totp_secret)
                    test_code = totp_service.generate()
                    if totp_service.verify(test_code):
                        logger.info("TOTP secret loaded (password) - self-test OK")
                        return True
                except Exception as e:
                    logger.debug("Strategy 1 (password) failed: %s", e)

            if ks.global_secret:
                try:
                    gs_key = bytes(ks.global_secret).hex()
                    totp_secret = database.decrypt_secret(enc_dict, gs_key)
                    if len(totp_secret) == 20:
                        totp_service.set_raw_secret(totp_secret)
                    else:
                        totp_service.set_secret(totp_secret)
                    test_code = totp_service.generate()
                    if totp_service.verify(test_code):
                        logger.info("TOTP secret loaded (global_secret) - self-test OK")
                        return True
                except Exception as e:
                    logger.debug("Strategy 2 (gs_hex) failed: %s", e)
                finally:
                    if 'gs_key' in locals() and isinstance(gs_key, str):
                        gs_key = None

            logger.warning("All decryption strategies failed for stored TOTP secret")
        else:
            logger.debug("No TOTP secret found in database")

        if ks.global_secret and not row:
            try:
                totp_service.set_secret(bytes(ks.global_secret))
                logger.info("TOTP secret derived from global_secret (legacy mode)")
                return True
            except Exception as e:
                logger.warning("Legacy TOTP derivation failed: %s", e)

        return False

    def persist_totp_secret(self, secret_bytes, password=None):
        enc_key = None
        key_label = "none"
        if password:
            enc_key = password
            key_label = "password"
        elif self._ks.global_secret:
            enc_key = bytes(self._ks.global_secret).hex()
            key_label = "global_secret_hex"

        if enc_key is None:
            logger.warning("TOTP secret NOT persisted - no encryption key available")
            return

        try:
            enc_dict = database.encrypt_secret(secret_bytes, enc_key)
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_SECRET_KEY, json.dumps(enc_dict))
                )
                conn.commit()
            logger.info("TOTP secret persisted (%d bytes, key=%s)", len(secret_bytes), key_label)
        except Exception as e:
            logger.error("Failed to persist TOTP secret: %s", e)

    def is_totp_setup_complete(self):
        try:
            with closing(database.get_connection()) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
                ).fetchone()
                return row is not None and row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP setup status: %s", e)
            return False

    def set_totp_setup_complete(self, value):
        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_SETUP_KEY, "1" if value else "0")
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to set TOTP setup status: %s", e)

    def is_totp_enabled(self):
        try:
            with closing(database.get_connection()) as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key=?", (TOTP_ENABLED_KEY,)
                ).fetchone()
                if row is None:
                    setup_row = conn.execute(
                        "SELECT value FROM settings WHERE key=?", (TOTP_SETUP_KEY,)
                    ).fetchone()
                    return setup_row is not None and setup_row[0] == "1"
                return row[0] == "1"
        except Exception as e:
            logger.warning("Failed to check TOTP enabled status: %s", e)
            return False

    def set_totp_enabled(self, value):
        try:
            with closing(database.get_connection()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (TOTP_ENABLED_KEY, "1" if value else "0")
                )
                conn.commit()
        except Exception as e:
            logger.error("Failed to set TOTP enabled status: %s", e)
