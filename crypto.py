"""
Hybrid Encryption (AES-GCM + RSA-OAEP) with time-based keys,
sliding window, and self-destruct.
"""

import secrets
import struct
import time as time_module
from typing import Tuple, Optional, TypedDict
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib

# Cryptographic constants
AES_KEY_SIZE = 32       # 256-bit AES key
NONCE_SIZE = 12         # 96-bit nonce for AES-GCM
TIME_STEP = 30          # Time-based key rotation interval (seconds)
WINDOW_SIZE = 2         # Sliding window size: ±2 steps (±60 seconds tolerance)
SELF_DESTRUCT_FLAG = 4  # Bit flag for self-destruct messages

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

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> bytes:
    """Encrypt with AES-GCM, optionally binding additional authenticated data (AAD)."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct

def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = None) -> bytes:
    """Decrypt with AES-GCM, verifying optional additional authenticated data (AAD)."""
    if len(data) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short")
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
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
    except Exception:
        return False

def sha256_fingerprint(data: bytes) -> str:
    """Return full 256-bit fingerprint as 64 hex characters."""
    return hashlib.sha256(data).hexdigest()

def format_fingerprint_display(hex_fingerprint: str) -> str:
    """Format a 64-char hex fingerprint for display with colon separators.
    Example: 'A1:B2:C3:...'
    """
    pairs = [hex_fingerprint[i:i+2] for i in range(0, len(hex_fingerprint), 2)]
    return ":".join(pairs).upper()

def pubkey_to_pem(pub_key) -> str:
    """Convert a public key object to its PEM string."""
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

class EncryptOptions(TypedDict, total=False):
    sign: bool
    my_priv: object
    encrypt_for_friend_pub: object
    self_destruct_seconds: Optional[int]

def encrypt_message(plaintext: bytes, const_key: bytes, timestamp: float,
                    **kwargs) -> Tuple[bytes, int]:
    """kwargs: sign, my_priv, encrypt_for_friend_pub, self_destruct_seconds"""
    sign = kwargs.get('sign', False)
    my_priv = kwargs.get('my_priv')
    encrypt_for_friend_pub = kwargs.get('encrypt_for_friend_pub')
    self_destruct_seconds = kwargs.get('self_destruct_seconds')

    flags = 0
    if sign:
        flags |= 1
    if encrypt_for_friend_pub:
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        flags |= 2
    else:
        aes_key = derive_time_key(const_key, int(timestamp))

    inner = struct.pack(">Q", int(timestamp))
    if self_destruct_seconds is not None and self_destruct_seconds > 0:
        flags |= SELF_DESTRUCT_FLAG
        inner += struct.pack(">I", self_destruct_seconds)
    inner += plaintext

    signature = b""
    if sign and my_priv:
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
    if sign:
        packet += _pack_bytes(signature)
    if encrypt_for_friend_pub:
        packet += _pack_bytes(encrypted_key)
    packet += ciphertext
    return packet, int(timestamp)

def decrypt_message(packet: bytes, const_key: bytes, my_priv=None,
                    friends=None, now: Optional[int] = None) -> str:
    if len(packet) < 1:
        raise ValueError("Invalid message format")
    flags = packet[0]
    idx = 1
    sign = bool(flags & 1)
    friend_encrypted = bool(flags & 2)
    has_self_destruct = bool(flags & SELF_DESTRUCT_FLAG)

    # Read the outer timestamp (always present after flags byte)
    if len(packet) < idx + 8:
        raise ValueError("Invalid message format")
    outer_ts = struct.unpack(">Q", packet[idx:idx+8])[0]
    idx += 8

    signature = b""
    if sign:
        signature, idx = _unpack_bytes(packet, idx)

    # Reconstruct AAD from outer header fields (must match encryption side exactly)
    aad = bytes([flags]) + struct.pack(">Q", outer_ts)
    if sign:
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
        # First try the exact timestamp from the outer header
        try:
            candidate_key = derive_time_key(const_key, outer_ts)
            inner = aes_gcm_decrypt(candidate_key, ciphertext, aad=aad)
            aes_key = candidate_key
        except Exception:
            # Fall back to sliding window around current time
            for step_offset in range(-WINDOW_SIZE, WINDOW_SIZE+1):
                candidate_timestamp = now + step_offset * TIME_STEP
                try:
                    candidate_key = derive_time_key(const_key, candidate_timestamp)
                    inner = aes_gcm_decrypt(candidate_key, ciphertext, aad=aad)
                    aes_key = candidate_key
                    break
                except Exception:
                    continue
        if inner is None:
            raise ValueError("Decryption failed – wrong key or stale message")

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
    if sign:
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