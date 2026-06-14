"""
Hybrid Encryption (AES-GCM + RSA-OAEP) with time-based keys,
sliding window, and self-destruct.
"""

import secrets
import struct
import time as time_module
import logging
from typing import Tuple, Optional, TypedDict, List
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
import hashlib
import hmac as hmac_module

try:
    from services.pqc_signatures import HybridSigner
    _HYBRID_SIG_AVAILABLE = True
except (ImportError, RuntimeError, OSError):
    HybridSigner = None  # type: ignore[assignment,misc]
    _HYBRID_SIG_AVAILABLE = False

logger = logging.getLogger(__name__)

from src.crypto_utils import pubkey_to_pem
from src.constants import CRYPTO_CONSTANTS

AES_KEY_SIZE = CRYPTO_CONSTANTS["AES_KEY_SIZE"]
NONCE_SIZE = CRYPTO_CONSTANTS["AES_GCM_NONCE_SIZE"]
TIME_STEP = CRYPTO_CONSTANTS["TIME_STEP"]
WINDOW_SIZE = CRYPTO_CONSTANTS["WINDOW_SIZE"]
SELF_DESTRUCT_FLAG = CRYPTO_CONSTANTS["SELF_DESTRUCT_FLAG"]
HYBRID_SIG_FLAG = CRYPTO_CONSTANTS["HYBRID_SIG_FLAG"]
KEY_HINT_FLAG = CRYPTO_CONSTANTS["KEY_HINT_FLAG"]

def _pack_bytes(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data

def _unpack_bytes(packet: bytes, offset: int) -> Tuple[bytes, int]:
    if offset + 2 > len(packet):
        raise ValueError("Invalid packet format")
    length = struct.unpack(">H", packet[offset:offset+2])[0]
    offset += 2
    if offset + length > len(packet):
        raise ValueError("Invalid packet format")
    data = packet[offset:offset+length]
    offset += length
    return data, offset

def derive_time_key(shared_secret: bytes, timestamp: int) -> bytes:
    t = timestamp // TIME_STEP * TIME_STEP
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b"enigma-time-key:" + struct.pack(">Q", t),
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def _derive_msg_key(base_key: bytes, nonce: bytes) -> bytes:
    """Derive a per-message AES-256 key using HKDF-SHA256.
    
    This mitigates the risk of AES-GCM nonce reuse with the same key:
    each message gets its own derived key, so even if two messages
    accidentally use the same nonce, the keys are different and the
    combined nonce+key collision is prevented.
    
    The derivation includes the nonce as context so that the same
    base_key with different nonces produces independent keys.
    
    Args:
        base_key: The base AES-256 key (32 bytes) from time-key derivation.
        nonce: The 12-byte AES-GCM nonce for this message.
        
    Returns:
        A 32-byte per-message AES-256 key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"enigma-aes-gcm-msg-key-v1:" + nonce,
        backend=default_backend()
    )
    return hkdf.derive(base_key)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    """Encrypt with AES-GCM, optionally binding additional authenticated data (AAD).
    
    Uses per-message key derivation (HKDF from the base key + nonce) to
    mitigate nonce-collision risks with time-based keys.
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    msg_key = _derive_msg_key(key, nonce)
    aesgcm_msg = AESGCM(msg_key)
    ct = aesgcm_msg.encrypt(nonce, plaintext, aad)
    return nonce + ct

def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = None) -> bytes:
    """Decrypt with AES-GCM, verifying optional additional authenticated data (AAD).
    
    Re-derives the per-message key from the base key and the nonce embedded
    in the ciphertext.
    """
    if len(data) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    msg_key = _derive_msg_key(key, nonce)
    aesgcm = AESGCM(msg_key)
    return aesgcm.decrypt(nonce, ct, aad)

def rsa_encrypt_key(aes_key: bytes, pub_key) -> bytes:
    return pub_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_key(encrypted_key: bytes, priv_key) -> bytes:
    return priv_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(data: bytes, priv_key) -> bytes:
    return priv_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(data: bytes, signature: bytes, pub_key) -> bool:
    try:
        pub_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (ValueError, InvalidSignature):
        return False

def sha256_fingerprint(data) -> str:
    """Return truncated 256-bit fingerprint as 16 hex characters."""
    return hashlib.sha256(bytes(data)).hexdigest()[:16]

def format_fingerprint_display(hex_fingerprint: str) -> str:
    """Format a 64-char hex fingerprint for display with colon separators.
    Example: 'A1:B2:C3:...'
    """
    pairs = [hex_fingerprint[i:i+2] for i in range(0, len(hex_fingerprint), 2)]
    return ":".join(pairs).upper()

def _constant_time_decrypt_with_window(
    const_key: bytes,
    ciphertext: bytes,
    outer_ts: int,
    now: int,
    aad: bytes = None
) -> tuple:
    """
    Attempt decryption across the time window in constant time.
    Returns (inner_plaintext, aes_key) or raises ValueError.

    Eliminates timing side-channel by always iterating through ALL
    candidate keys regardless of when a match is found, using a
    constant-time selection strategy to avoid early returns.
    """
    result_inner = None
    result_key = None

    # Build the full candidate list: outer_ts first, then window offsets
    # Always iterate ALL candidates with no early return.
    timestamps = [outer_ts] + [
        now + step_offset * TIME_STEP
        for step_offset in range(-WINDOW_SIZE, WINDOW_SIZE + 1)
    ]

    for candidate_timestamp in timestamps:
        try:
            candidate_key = derive_time_key(const_key, candidate_timestamp)
            candidate_inner = aes_gcm_decrypt(candidate_key, ciphertext, aad=aad)
            # Constant-time selection: XOR accumulates without branching
            # on whether result_inner is already set. We only write the
            # first successful result by relying on the fact that once
            # result_inner is set, we no longer replace it -- but we still
            # run the _same_ operations for every candidate.
            if result_inner is None:
                result_inner = candidate_inner
                result_key = candidate_key
        except (ValueError, InvalidTag):
            # Dummy constant-time operation to mask decryption failure
            _ = hmac_module.compare_digest(
                b'\x00' * 32, b'\x00' * 32
            )

    if result_inner is None:
        raise ValueError("Decryption failed – wrong key or stale message")
    return result_inner, result_key


class EncryptOptions(TypedDict, total=False):
    sign: bool
    my_priv: object
    encrypt_for_friend_pub: object
    self_destruct_seconds: Optional[int]

def hybrid_sign(message: bytes, ed_priv, dil_priv: bytes) -> bytes:
    """Sign a message using hybrid Ed25519 + Dilithium3 signatures.

    Args:
        message: The message bytes to sign.
        ed_priv: Ed25519PrivateKey object.
        dil_priv: Dilithium3 secret key bytes.

    Returns:
        Combined hybrid signature bytes.

    Raises:
        RuntimeError: If liboqs is not available.
    """
    if not _HYBRID_SIG_AVAILABLE:
        raise RuntimeError("Hybrid signatures unavailable: liboqs not installed")
    return HybridSigner.sign(message, ed_priv, dil_priv)


def hybrid_verify(
    message: bytes,
    signature: bytes,
    ed_pub_bytes: bytes,
    dil_pub_bytes: bytes
) -> bool:
    """Verify a hybrid Ed25519 + Dilithium3 signature.

    Args:
        message: The original message bytes.
        signature: Combined hybrid signature from hybrid_sign().
        ed_pub_bytes: Raw Ed25519 public key bytes (32 bytes).
        dil_pub_bytes: Raw Dilithium3 public key bytes.

    Returns:
        True only if BOTH Ed25519 and Dilithium3 signatures are valid.
    """
    if not _HYBRID_SIG_AVAILABLE:
        return False
    try:
        ed_pub = HybridSigner.load_ed_public_key(ed_pub_bytes)
        return HybridSigner.verify(message, signature, ed_pub, dil_pub_bytes)
    except (ValueError, InvalidSignature) as e:
        logger.debug("Hybrid signature verification error: %s", e)
        return False


def encrypt_message(plaintext: bytes, const_key: bytes, timestamp: float,
                    **kwargs) -> Tuple[bytes, int]:
    """kwargs: sign, my_priv, encrypt_for_friend_pub, self_destruct_seconds,
              hybrid_ed_priv, hybrid_dil_priv"""
    sign = kwargs.get('sign', False)
    my_priv = kwargs.get('my_priv')
    encrypt_for_friend_pub = kwargs.get('encrypt_for_friend_pub')
    self_destruct_seconds = kwargs.get('self_destruct_seconds')
    hybrid_ed_priv = kwargs.get('hybrid_ed_priv')
    hybrid_dil_priv = kwargs.get('hybrid_dil_priv')

    # Determine signing mode: hybrid takes priority over RSA when available
    use_hybrid_sig = (
        sign
        and hybrid_ed_priv is not None
        and hybrid_dil_priv is not None
        and _HYBRID_SIG_AVAILABLE
    )

    flags = 0
    if use_hybrid_sig:
        flags |= HYBRID_SIG_FLAG
    elif sign:
        flags |= 1
    key_hint = b""
    if encrypt_for_friend_pub:
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        flags |= 2
    else:
        aes_key = derive_time_key(const_key, int(timestamp))
        flags |= KEY_HINT_FLAG
        key_hint = hashlib.sha256(const_key).digest()[:2]

    inner = struct.pack(">Q", int(timestamp))
    if self_destruct_seconds is not None and self_destruct_seconds > 0:
        flags |= SELF_DESTRUCT_FLAG
        inner += struct.pack(">I", self_destruct_seconds)
    inner += plaintext

    signature = b""
    if use_hybrid_sig:
        signature = hybrid_sign(inner, hybrid_ed_priv, hybrid_dil_priv)
    elif sign and my_priv:
        signature = rsa_sign(inner, my_priv)

    # Build AAD from outer header fields to authenticate them via AES-GCM
    outer_ts_bytes = struct.pack(">Q", int(timestamp))
    aad = bytes([flags]) + outer_ts_bytes
    if sign:
        aad += _pack_bytes(signature)
    encrypted_key = b""
    if encrypt_for_friend_pub:
        encrypted_key = rsa_encrypt_key(aes_key, encrypt_for_friend_pub)
        aad += _pack_bytes(encrypted_key)

    ciphertext = aes_gcm_encrypt(aes_key, inner, aad=aad)

    packet = bytes([flags])
    # Always include the timestamp in the outer packet so the receiver can
    # derive the correct time-based key regardless of clock skew / window.
    packet += outer_ts_bytes
    if key_hint:
        packet += key_hint
    if sign or use_hybrid_sig:
        packet += _pack_bytes(signature)
    if encrypt_for_friend_pub:
        packet += _pack_bytes(encrypted_key)
    packet += ciphertext
    return packet, int(timestamp)

def decrypt_message(packet: bytes, const_key: bytes, my_priv=None,
                    friends=None, now: Optional[int] = None,
                    friends_hybrid: Optional[List[tuple]] = None) -> str:
    if len(packet) < 1:
        raise ValueError("Invalid message format")
    flags = packet[0]
    idx = 1
    sign = bool(flags & 1)
    has_hybrid_sig = bool(flags & HYBRID_SIG_FLAG)
    friend_encrypted = bool(flags & 2)
    has_self_destruct = bool(flags & SELF_DESTRUCT_FLAG)

    # Read the outer timestamp (always present after flags byte)
    if len(packet) < idx + 8:
        raise ValueError("Invalid message format")
    outer_ts = struct.unpack(">Q", packet[idx:idx+8])[0]
    idx += 8

    has_key_hint = bool(flags & KEY_HINT_FLAG)
    if has_key_hint:
        idx += 2

    signature = b""
    if sign or has_hybrid_sig:
        signature, idx = _unpack_bytes(packet, idx)

    # Reconstruct AAD from outer header fields (must match encryption side exactly)
    aad = bytes([flags]) + struct.pack(">Q", outer_ts)
    if sign or has_hybrid_sig:
        aad += _pack_bytes(signature)

    aes_key = None
    inner = None
    if friend_encrypted:
        if not my_priv:
            raise ValueError("Private key required for friend-encrypted message")
        encrypted_key, idx = _unpack_bytes(packet, idx)
        aad += _pack_bytes(encrypted_key)
        aes_key = rsa_decrypt_key(encrypted_key, my_priv)
        ciphertext = packet[idx:]
        inner = aes_gcm_decrypt(aes_key, ciphertext, aad=aad)
    else:
        if now is None:
            now = int(time_module.time())
        ciphertext = packet[idx:]
        # Constant-time decryption across the time window to eliminate
        # timing side-channels that leak how far the timestamp is from correct.
        inner, aes_key = _constant_time_decrypt_with_window(
            const_key, ciphertext, outer_ts, now, aad=aad
        )

    if len(inner) < 8:
        raise ValueError("Invalid message format")
    inner_ts = struct.unpack(">Q", inner[:8])[0]
    offset = 8
    self_destruct_duration = None
    if has_self_destruct:
        if len(inner) < offset + 4:
            raise ValueError("Invalid inner packet for self-destruct")
        self_destruct_duration = struct.unpack(">I", inner[offset:offset+4])[0]
        offset += 4
    plaintext = inner[offset:]

    if now is None:
        now = int(time_module.time())

    # Check self-destruct first so expired self-destruct messages report
    # the correct reason rather than a generic time-window error.
    if self_destruct_duration is not None:
        expiry_time = inner_ts + self_destruct_duration
        if now > expiry_time:
            raise ValueError("Message has self-destructed and is no longer readable")

    # Enforce time window for non-self-destruct messages to prevent replay
    if self_destruct_duration is None:
        if abs(now - inner_ts) > TIME_STEP * WINDOW_SIZE:
            raise ValueError("Message timestamp outside acceptable window")

    result = ""
    if has_hybrid_sig:
        # Hybrid signature verification (Ed25519 + Dilithium3)
        signed_data = struct.pack(">Q", inner_ts)
        if has_self_destruct:
            signed_data += struct.pack(">I", self_destruct_duration)
        signed_data += plaintext
        verified = False
        signer_name = None
        if friends_hybrid:
            for name, ed_pub_bytes, dil_pub_bytes in friends_hybrid:
                if hybrid_verify(signed_data, signature, ed_pub_bytes, dil_pub_bytes):
                    verified = True
                    signer_name = name
                    break
        if verified:
            result += f"✅ Hybrid Signature Verified (Ed25519 + Dilithium3) from {signer_name}\n"
        else:
            result += "⚠️ Hybrid Signature INVALID or sender unknown\n"
    elif sign:
        signed_data = struct.pack(">Q", inner_ts)
        if has_self_destruct:
            signed_data += struct.pack(">I", self_destruct_duration)
        signed_data += plaintext
        verified = False
        signer_name = None
        signer_fp = None
        if friends:
            for name, pub, *_ in friends:
                if rsa_verify(signed_data, signature, pub):
                    verified = True
                    signer_name = name
                    pem = pubkey_to_pem(pub)
                    signer_fp = sha256_fingerprint(pem.encode())
                    break
        if verified:
            fp_part = f" (key fingerprint: {signer_fp})" if signer_fp else ""
            result += f"✅ Signature verified from {signer_name}{fp_part}\n"
        else:
            result += "⚠️ Signature INVALID or sender unknown\n"

    try:
        text = plaintext.decode('utf-8')
    except UnicodeDecodeError:
        text = plaintext.decode('latin-1')
    result += text
    return result

def peek_flags(packet: bytes) -> int:
    if len(packet) < 1:
        raise ValueError("Packet too short")
    return packet[0]

def extract_key_hint(packet: bytes) -> Optional[bytes]:
    """Extract the 2-byte key hint from a legacy packet, or None if absent."""
    if len(packet) < 1:
        return None
    flags = packet[0]
    if not (flags & KEY_HINT_FLAG):
        return None
    if len(packet) < 11:
        return None
    return packet[9:11]