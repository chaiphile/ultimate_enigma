"""Comprehensive unit tests for services/shamir_service.py – Shamir Secret Sharing."""

import pytest
from itertools import combinations

from services.shamir_service import ShamirService, generate_recovery_key
from src.exceptions import ShamirError, InsufficientSharesError, InvalidShareError


# ---------------------------------------------------------------------------
# Tests: ShamirService
# ---------------------------------------------------------------------------

class TestShamirService:
    def setup_method(self):
        self.svc = ShamirService()

    def test_split_and_reconstruct_basic(self):
        """Split a secret and reconstruct it exactly."""
        secret = b'\x01' * 32
        shares = self.svc.split_secret(secret, num_shares=3, threshold=2)
        assert len(shares) == 3
        reconstructed = self.svc.reconstruct_secret(shares[:2], expected_length=32)
        assert reconstructed == secret

    def test_split_and_reconstruct_all_shares(self):
        """Reconstruct using all shares."""
        secret = b'\xAB\xCD' * 16
        shares = self.svc.split_secret(secret, num_shares=5, threshold=5)
        reconstructed = self.svc.reconstruct_secret(shares, expected_length=32)
        assert reconstructed == secret

    def test_any_k_shares_work(self):
        """Any K shares should reconstruct the same secret."""
        secret = b'\xFF' * 16
        shares = self.svc.split_secret(secret, num_shares=4, threshold=3)
        for combo in combinations(range(4), 3):
            subset = [shares[i] for i in combo]
            reconstructed = self.svc.reconstruct_secret(subset, expected_length=16)
            assert reconstructed == secret, f"Failed for combination {combo}"

    def test_different_shares_produce_different_output(self):
        """Different splits should produce different share values."""
        secret = b'\x42' * 32
        shares1 = self.svc.split_secret(secret, num_shares=3, threshold=2)
        shares2 = self.svc.split_secret(secret, num_shares=3, threshold=2)
        assert shares1[0][1] != shares2[0][1]

    def test_insufficient_shares_raises(self):
        """Fewer than 2 shares should raise InsufficientSharesError."""
        secret = b'\x01' * 32
        shares = self.svc.split_secret(secret, num_shares=5, threshold=3)
        with pytest.raises(InsufficientSharesError):
            self.svc.reconstruct_secret(shares[:1], expected_length=32)

    def test_invalid_threshold_raises(self):
        """Threshold < 2 should raise ShamirError."""
        secret = b'\x01' * 32
        with pytest.raises(ShamirError):
            self.svc.split_secret(secret, num_shares=3, threshold=1)

    def test_threshold_exceeds_shares_raises(self):
        """Threshold > num_shares should raise ShamirError."""
        secret = b'\x01' * 32
        with pytest.raises(ShamirError):
            self.svc.split_secret(secret, num_shares=2, threshold=3)

    def test_num_shares_exceeds_max_raises(self):
        """num_shares > 10 should raise ShamirError."""
        secret = b'\x01' * 32
        with pytest.raises(ShamirError):
            self.svc.split_secret(secret, num_shares=11, threshold=2)

    def test_generate_recovery_key(self):
        """generate_recovery_key returns correct length."""
        key = generate_recovery_key(32)
        assert len(key) == 32
        key2 = generate_recovery_key(32)
        assert key != key2

    def test_generate_recovery_key_custom_size(self):
        """generate_recovery_key respects custom size."""
        key = generate_recovery_key(16)
        assert len(key) == 16

    def test_empty_secret_raises(self):
        """Empty secret should raise ShamirError."""
        with pytest.raises(ShamirError):
            self.svc.split_secret(b'', num_shares=3, threshold=2)

    def test_single_byte_secret(self):
        """Secret of 1 byte should work."""
        secret = b'\x7F'
        shares = self.svc.split_secret(secret, num_shares=3, threshold=2)
        reconstructed = self.svc.reconstruct_secret(shares[:2], expected_length=1)
        assert reconstructed == secret

    def test_share_indices_are_1indexed(self):
        """Share indices should be 1-indexed."""
        secret = b'\x01' * 8
        shares = self.svc.split_secret(secret, num_shares=4, threshold=2)
        indices = [s[0] for s in shares]
        assert indices == [1, 2, 3, 4]

    def test_share_length_matches_secret(self):
        """Each share should be the same length as the secret."""
        secret = b'\xAA' * 64
        shares = self.svc.split_secret(secret, num_shares=5, threshold=3)
        for idx, share_bytes in shares:
            assert len(share_bytes) == 64

    def test_mismatched_share_lengths_raises(self):
        """Shares with different lengths should raise InvalidShareError."""
        bad_shares = [
            (1, b'\x01' * 32),
            (2, b'\x02' * 16),
        ]
        with pytest.raises(InvalidShareError):
            self.svc.reconstruct_secret(bad_shares, expected_length=32)

    def test_zero_threshold_raises(self):
        """Threshold of 0 should raise ShamirError."""
        with pytest.raises(ShamirError):
            self.svc.split_secret(b'\x01' * 32, num_shares=3, threshold=0)

    def test_large_secret(self):
        """Larger secrets should split and reconstruct correctly."""
        secret = bytes(range(256)) * 4  # 1024 bytes
        shares = self.svc.split_secret(secret, num_shares=3, threshold=2)
        reconstructed = self.svc.reconstruct_secret(shares[:2], expected_length=1024)
        assert reconstructed == secret

    def test_threshold_equals_num_shares(self):
        """When threshold == num_shares, all shares are required."""
        secret = b'\xBE' * 32
        shares = self.svc.split_secret(secret, num_shares=3, threshold=3)
        reconstructed = self.svc.reconstruct_secret(shares, expected_length=32)
        assert reconstructed == secret

    def test_minimum_valid_params(self):
        """Minimum valid params: 2 shares, threshold 2."""
        secret = b'\x01' * 4
        shares = self.svc.split_secret(secret, num_shares=2, threshold=2)
        assert len(shares) == 2
        reconstructed = self.svc.reconstruct_secret(shares, expected_length=4)
        assert reconstructed == secret


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
