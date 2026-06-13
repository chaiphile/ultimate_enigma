"""Shamir's Secret Sharing over GF(256) for key recovery.

Implements (t, n) secret splitting where t shares are required to
reconstruct the original secret. Each byte is processed independently
through a random polynomial over GF(256).
"""

import logging
import secrets
from typing import List, Tuple

from src.exceptions import (
    ShamirError,
    InsufficientSharesError,
    InvalidShareError,
)

logger = logging.getLogger(__name__)

_IRREDUCIBLE = 0x11D

_GF_EXP: List[int] = [0] * 512
_GF_LOG: List[int] = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _IRREDUCIBLE
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_build_tables()


def _gf_add(a: int, b: int) -> int:
    return a ^ b


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_pow(base: int, exp: int) -> int:
    if exp == 0:
        return 1
    if base == 0:
        return 0
    return _GF_EXP[(_GF_LOG[base] * exp) % 255]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Cannot invert 0 in GF(256)")
    return _GF_EXP[255 - _GF_LOG[a]]


def _eval_poly(coeffs: List[int], x: int) -> int:
    result = 0
    power = 1
    for c in coeffs:
        result = _gf_add(result, _gf_mul(c, power))
        power = _gf_mul(power, x)
    return result


class ShamirService:
    """Shamir's Secret Sharing over GF(256)."""

    def __init__(self) -> None:
        pass

    def split_secret(
        self, secret: bytes, num_shares: int, threshold: int
    ) -> List[Tuple[int, bytes]]:
        """Split a secret into shares requiring threshold shares to reconstruct.

        Args:
            secret: The secret bytes to split.
            num_shares: Total number of shares to generate.
            threshold: Minimum shares required for reconstruction.

        Returns:
            List of (share_index, share_bytes) tuples, 1-indexed.

        Raises:
            ShamirError: If parameters are invalid.
        """
        if len(secret) == 0:
            raise ShamirError("Secret must not be empty")
        if threshold < 2:
            raise ShamirError("Threshold must be at least 2")
        if num_shares < threshold:
            raise ShamirError("num_shares must be >= threshold")
        if num_shares > 10:
            raise ShamirError("num_shares must be <= 10")

        shares: List[List[int]] = [[] for _ in range(num_shares)]

        for byte_val in secret:
            coeffs = [byte_val]
            for _ in range(threshold - 1):
                coeffs.append(secrets.randbelow(256))

            for i in range(num_shares):
                x = i + 1
                shares[i].append(_eval_poly(coeffs, x))

        result = [(i + 1, bytes(shares[i])) for i in range(num_shares)]
        logger.info(
            "Split secret into %d shares (threshold=%d, length=%d)",
            num_shares,
            threshold,
            len(secret),
        )
        return result

    def reconstruct_secret(
        self,
        shares: List[Tuple[int, bytes]],
        expected_length: int,
    ) -> bytes:
        """Reconstruct a secret from shares using Lagrange interpolation.

        Args:
            shares: List of (share_index, share_bytes) tuples.
            expected_length: Expected length of the original secret.

        Returns:
            The reconstructed secret bytes.

        Raises:
            InsufficientSharesError: If fewer than 2 shares provided.
            InvalidShareError: If shares have mismatched lengths.
        """
        if len(shares) < 2:
            raise InsufficientSharesError(
                f"Need at least 2 shares, got {len(shares)}"
            )

        lengths = {len(s[1]) for s in shares}
        if len(lengths) != 1:
            raise InvalidShareError("Shares have mismatched lengths")
        actual_length = next(iter(lengths))
        if actual_length != expected_length:
            raise InvalidShareError(
                f"Share length {actual_length} != expected {expected_length}"
            )

        indices = [s[0] for s in shares]
        share_bytes_list = [s[1] for s in shares]

        result = bytearray(expected_length)
        for byte_idx in range(expected_length):
            points = [share_bytes_list[si][byte_idx] for si in range(len(shares))]
            coeffs = self._lagrange_coefficients(0, indices)
            val = 0
            for i, c in enumerate(coeffs):
                val = _gf_add(val, _gf_mul(points[i], c))
            result[byte_idx] = val

        logger.info("Reconstructed secret from %d shares", len(shares))
        return bytes(result)

    def _lagrange_coefficients(self, x: int, points: List[int]) -> List[int]:
        """Compute Lagrange basis polynomial coefficients at x.

        Args:
            x: The point to evaluate the interpolation at.
            points: The x-coordinates of the known points.

        Returns:
            List of Lagrange basis coefficients, one per input point.
        """
        n = len(points)
        coefficients = []

        for i in range(n):
            basis = [1]
            denom = 1
            xi = points[i]
            for j in range(n):
                if i == j:
                    continue
                xj = points[j]
                # Multiply basis by (x - xj)
                new_basis = [0] * (len(basis) + 1)
                for k, c in enumerate(basis):
                    new_basis[k] = _gf_add(new_basis[k], _gf_mul(c, xj))
                    new_basis[k + 1] = _gf_add(new_basis[k + 1], c)
                basis = new_basis
                denom = _gf_mul(denom, _gf_add(xi, xj))

            # Evaluate basis polynomial at x
            val = 0
            power = 1
            for k, c in enumerate(basis):
                val = _gf_add(val, _gf_mul(c, power))
                power = _gf_mul(power, x)

            # Multiply by 1/denom
            coefficients.append(_gf_mul(val, _gf_inv(denom)))

        return coefficients


def generate_recovery_key(size: int = 32) -> bytes:
    """Generate a cryptographically random recovery key.

    Args:
        size: Number of bytes to generate (default 32).

    Returns:
        Random key bytes.
    """
    return secrets.token_bytes(size)
