"""SecureString wrapper for handling sensitive string data (passwords, secrets).

This module provides a SecureString class that wraps sensitive string data in a
bytearray internally, allowing for secure memory wiping when the data is no longer
needed. Unlike Python's immutable str type, bytearray contents can be zeroed out
to minimize exposure of sensitive data in memory.

Usage:
    # Using as context manager (recommended)
    with SecureString("my_password") as secure_pw:
        use_password(secure_pw.to_str())
    # Memory is automatically wiped after the context

    # Manual usage
    secure_pw = SecureString("my_password")
    try:
        use_password(secure_pw.to_str())
    finally:
        secure_pw.wipe()

Security Notes:
    - Python's garbage collector may still leave copies in memory
    - String interning and caching may create additional copies
    - For maximum security, always use context managers
    - Call wipe() explicitly when done with the data
"""

import hmac
import secrets
import logging
from typing import Optional, Union

from security.memory_security import mlock_memory, munlock_memory

logger = logging.getLogger(__name__)


class SecureString:
    """A wrapper for sensitive string data that can be securely wiped from memory.

    Internally stores data as a bytearray which can be zeroed out.
    Provides methods for safe comparison, conversion, and cleanup.

    Attributes:
        _data: Internal bytearray storage (None after wipe).
        _wiped: Flag indicating if the data has been wiped.
    """

    def __init__(self, data: Optional[Union[str, bytes, bytearray]] = None):
        """Initialize SecureString with optional data.

        Args:
            data: Initial data as str, bytes, or bytearray. If str, encoded as UTF-8.
        """
        self._wiped = False
        self._mlocked = False
        if data is None:
            self._data = bytearray()
        elif isinstance(data, str):
            self._data = bytearray(data.encode('utf-8'))
        elif isinstance(data, (bytes, bytearray)):
            self._data = bytearray(data)
        else:
            raise TypeError(f"SecureString expects str, bytes, or bytearray, got {type(data)}")

    def __enter__(self) -> "SecureString":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager and wipe data."""
        self.wipe()

    def __len__(self) -> int:
        """Return the length of the stored data."""
        if self._wiped:
            return 0
        return len(self._data)

    def __bool__(self) -> bool:
        """Return True if the SecureString contains non-empty data and hasn't been wiped."""
        return not self._wiped and len(self._data) > 0

    def __repr__(self) -> str:
        """Return a safe representation that doesn't expose the actual data."""
        if self._wiped:
            return "SecureString(<wiped>)"
        return f"SecureString(<{len(self._data)} chars>)"

    def __str__(self) -> str:
        """Return a safe string representation (doesn't expose data)."""
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        """Constant-time equality comparison.

        Args:
            other: Another SecureString, str, bytes, or bytearray to compare with.

        Returns:
            True if contents are equal, False otherwise.
        """
        if self._wiped:
            return False

        if isinstance(other, SecureString):
            if other._wiped:
                return False
            other_data = other._data
        elif isinstance(other, str):
            other_data = other.encode('utf-8')
        elif isinstance(other, (bytes, bytearray)):
            other_data = other
        else:
            return False

        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(bytes(self._data), bytes(other_data))

    def __ne__(self, other: object) -> bool:
        """Constant-time inequality comparison."""
        return not self.__eq__(other)

    def __hash__(self) -> int:
        """Raise TypeError - SecureString should not be used as dict keys or in sets."""
        raise TypeError("unhashable type: 'SecureString' - do not use sensitive data as keys")

    def __del__(self) -> None:
        """Attempt to wipe data on garbage collection."""
        try:
            if not self._wiped:
                self.wipe()
        except Exception:
            pass

    def lock(self) -> None:
        """Lock the underlying bytearray in RAM to prevent swapping."""
        if self._data is not None and not self._mlocked and not self._wiped:
            self._mlocked = mlock_memory(self._data)

    def wipe(self) -> None:
        """Securely wipe the internal data by zeroing out the bytearray.

        After calling wipe(), the SecureString is considered empty and
        all access methods will return empty values or raise errors.
        """
        if self._wiped:
            return

        if self._mlocked and self._data is not None:
            munlock_memory(self._data)
            self._mlocked = False

        if self._data is not None:
            # Overwrite with zeros
            for i in range(len(self._data)):
                self._data[i] = 0
            # Overwrite with random data (defense against memory remanence)
            if len(self._data) > 0:
                random_data = secrets.token_bytes(len(self._data))
                for i in range(len(self._data)):
                    self._data[i] = random_data[i]
            # Final zeroing
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data = None

        self._wiped = True

    @property
    def is_wiped(self) -> bool:
        """Return True if the data has been wiped."""
        return self._wiped

    def to_str(self) -> str:
        """Convert the internal data to a Python string.

        WARNING: The returned string is immutable and cannot be securely wiped.
        Use the result immediately and discard references as soon as possible.

        Returns:
            The internal data as a UTF-8 string.

        Raises:
            RuntimeError: If the data has been wiped.
        """
        if self._wiped:
            raise RuntimeError("SecureString has been wiped and cannot be accessed")
        return self._data.decode('utf-8')

    def to_bytes(self) -> bytes:
        """Convert the internal data to bytes.

        WARNING: The returned bytes object is immutable and cannot be securely wiped.
        Use the result immediately and discard references as soon as possible.

        Returns:
            The internal data as bytes.

        Raises:
            RuntimeError: If the data has been wiped.
        """
        if self._wiped:
            raise RuntimeError("SecureString has been wiped and cannot be accessed")
        return bytes(self._data)

    def to_bytearray(self) -> bytearray:
        """Return a copy of the internal data as a mutable bytearray.

        The caller is responsible for wiping the returned bytearray when done.

        Returns:
            A copy of the internal data as bytearray.

        Raises:
            RuntimeError: If the data has been wiped.
        """
        if self._wiped:
            raise RuntimeError("SecureString has been wiped and cannot be accessed")
        return bytearray(self._data)

    def encode(self, encoding: str = 'utf-8') -> bytes:
        """Encode the internal data using the specified encoding.

        Args:
            encoding: Character encoding to use (default: 'utf-8').

        Returns:
            Encoded bytes.

        Raises:
            RuntimeError: If the data has been wiped.
        """
        if self._wiped:
            raise RuntimeError("SecureString has been wiped and cannot be accessed")
        return bytes(self._data).decode('utf-8').encode(encoding)

    def append(self, data: Union[bytes, bytearray, "SecureString"]) -> None:
        """Append data to the internal bytearray.

        Args:
            data: Data to append (bytes, bytearray, or SecureString).

        Raises:
            TypeError: If data is a str (creates non-wipeable copies).
            RuntimeError: If the data has been wiped.
        """
        if self._wiped:
            raise RuntimeError("SecureString has been wiped and cannot be modified")

        if isinstance(data, str):
            raise TypeError(
                "append() with str creates non-wipeable copies. "
                "Encode to bytes first."
            )
        elif isinstance(data, SecureString):
            if data._wiped:
                raise ValueError("Cannot append wiped SecureString")
            self._data.extend(data._data)
        elif isinstance(data, (bytes, bytearray)):
            self._data.extend(data)
        else:
            raise TypeError(f"Cannot append {type(data)} to SecureString")

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecureString":
        """Create a SecureString from bytes.

        Args:
            data: Bytes to wrap.

        Returns:
            New SecureString instance.
        """
        return cls(data)

    @classmethod
    def from_str(cls, data: str) -> "SecureString":
        """Create a SecureString from a string.

        Args:
            data: String to wrap.

        Returns:
            New SecureString instance.
        """
        return cls(data)

    def copy(self) -> "SecureString":
        """Create a deep copy of this SecureString.

        Returns:
            New SecureString with copied data.

        Raises:
            RuntimeError: If the data has been wiped.
        """
        if self._wiped:
            raise RuntimeError("SecureString has been wiped and cannot be copied")
        return SecureString(self._data)


def secure_compare(a: Union[SecureString, str, bytes], b: Union[SecureString, str, bytes]) -> bool:
    """Constant-time comparison of two sensitive values.

    This function should be used instead of == when comparing passwords
    or other sensitive values to prevent timing attacks.

    Args:
        a: First value (SecureString, str, or bytes).
        b: Second value (SecureString, str, or bytes).

    Returns:
        True if values are equal, False otherwise.
    """
    # Convert both to bytes for comparison
    def to_bytes(val):
        if isinstance(val, SecureString):
            if val._wiped:
                return b''
            return bytes(val._data)
        elif isinstance(val, str):
            return val.encode('utf-8')
        elif isinstance(val, (bytes, bytearray)):
            return bytes(val)
        else:
            raise TypeError(f"Cannot compare {type(val)}")

    a_bytes = to_bytes(a)
    b_bytes = to_bytes(b)

    return hmac.compare_digest(a_bytes, b_bytes)


def wipe_bytes(data: Union[bytes, bytearray, None]) -> None:
    """Attempt to wipe a bytes or bytearray object.

    Note: bytes objects are immutable in Python, so this function can only
    wipe bytearray objects. For bytes objects, the caller should ensure
    no references remain.

    Args:
        data: The bytes or bytearray to wipe.
    """
    if data is None:
        return
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    # For bytes, we can't modify in place, but we document the limitation
    # The caller should ensure references are dropped


def wipe_str(data: Optional[str]) -> None:
    """Document that a string should be wiped.

    Note: Python strings are immutable and cannot be wiped in place.
    This function exists to document intent. The caller should ensure
    all references to the string are dropped and gc.collect() is called.

    Args:
        data: The string that should be considered wiped.
    """
    # Strings are immutable in Python - we can't actually wipe them
    # This is a documentation function. The caller should:
    # 1. Set the variable to None
    # 2. Call gc.collect() to encourage garbage collection
    pass
