"""Tests for Help Peer SDK."""
import os
import json
import struct
import tempfile
import shutil
import pytest

from helppeer import crypto, erasure, manifest, validator
from helppeer.config import configure, get_config


class TestCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        k_data = b"\x00" * 32
        plaintext = b"Hello, Help Peer!"
        encrypted = crypto.encrypt_segment(k_data, plaintext)
        decrypted = crypto.decrypt_segment(k_data, encrypted)
        assert plaintext == decrypted

    def test_key_derivation_consistency(self):
        k1_data, k1_index = crypto.derive_keys("7-orbit-velvet")
        k2_data, k2_index = crypto.derive_keys("7-orbit-velvet")
        assert k1_data == k2_data
        assert k1_index == k2_index

        k3_data, _ = crypto.derive_keys("8-orbit-velvet")
        assert k1_data != k3_data

    def test_relay_hash_consistency(self):
        _, k_index = crypto.derive_keys("7-orbit-velvet")
        h1 = crypto.relay_hash(k_index)
        h2 = crypto.relay_hash(k_index)
        assert h1 == h2
        assert len(h1) == 64  # 32 bytes hex

    def test_hmac_verification(self):
        k_data = b"\x00" * 32
        shard = b"some shard data"
        h = crypto.shard_hmac(k_data, shard)
        assert crypto.verify_shard_hmac(k_data, shard, h)
        assert not crypto.verify_shard_hmac(k_data, b"tampered", h)


class TestErasure:
    def test_encode_decode_roundtrip(self):
        data = b"Hello, Help Peer! This is a test segment for erasure coding."
        shards = erasure.encode_segment(data)
        assert len(shards) == 12

        shard_opts = list(shards)
        reconstructed = erasure.decode_segment(shard_opts, len(data))
        assert data == reconstructed

    def test_decode_with_missing_parity(self):
        data = b"Test data for erasure coding with missing shards!"
        shards = erasure.encode_segment(data)

        # Drop 4 parity shards
        shard_opts = list(shards)
        for i in range(8, 12):
            shard_opts[i] = None
        reconstructed = erasure.decode_segment(shard_opts, len(data))
        assert data == reconstructed

    def test_decode_with_missing_data_shards(self):
        data = b"Test data for erasure coding with some data shards missing!"
        shards = erasure.encode_segment(data)

        # Drop 2 data + 2 parity
        shard_opts = list(shards)
        shard_opts[1] = None
        shard_opts[3] = None
        shard_opts[9] = None
        shard_opts[11] = None
        reconstructed = erasure.decode_segment(shard_opts, len(data))
        assert data == reconstructed

    def test_decode_insufficient_shards(self):
        data = b"Too many missing shards!"
        shards = erasure.encode_segment(data)

        shard_opts = list(shards)
        for i in range(5):
            shard_opts[i] = None

        with pytest.raises(ValueError, match="insufficient"):
            erasure.decode_segment(shard_opts, len(data))


class TestManifest:
    def test_build_from_dir(self, tmp_path):
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "model.safetensors").write_text("weights")

        m = manifest.build_manifest(str(tmp_path), "test-transfer", 67108864)
        assert m.transfer_name == "test-transfer"
        assert m.version == 1
        assert len(m.files) == 2
        assert m.total_bytes > 0

    def test_json_roundtrip(self):
        m = manifest.Manifest(
            transfer_name="test",
            total_bytes=100,
            segment_size=67108864,
            files=[
                manifest.ManifestFile(
                    path="test.txt",
                    size=100,
                    segments=[
                        manifest.ManifestSegment(
                            id="seg_000000",
                            original_size=100,
                            encrypted_size=0,
                        )
                    ],
                )
            ],
        )
        json_bytes = m.to_json()
        restored = manifest.Manifest.from_json(json_bytes)
        assert restored.transfer_name == "test"
        assert len(restored.files) == 1
        assert restored.files[0].path == "test.txt"


class TestValidator:
    def test_safetensors_valid(self):
        header = json.dumps({
            "__metadata__": {"format": "pt"},
            "weight1": {"dtype": "F32", "shape": [10, 10], "data_offsets": [0, 400]},
        }).encode()
        data = struct.pack("<Q", len(header)) + header
        v = validator.SafetensorsValidator()
        v.validate_first_segment(data)  # should not raise

    def test_safetensors_invalid_json(self):
        data = struct.pack("<Q", 5) + b"NOT{JSON"
        v = validator.SafetensorsValidator()
        with pytest.raises(validator.ValidationError):
            v.validate_first_segment(data)

    def test_safetensors_too_small(self):
        v = validator.SafetensorsValidator()
        with pytest.raises(validator.ValidationError):
            v.validate_first_segment(b"tiny")

    def test_generic_accepts_all(self):
        v = validator.GenericValidator()
        v.validate_first_segment(b"anything")
        v.validate_first_segment(b"")

    def test_registry_lookup(self):
        reg = validator.ValidatorRegistry()
        v = reg.validator_for("model.safetensors")
        assert "safetensors" in v.file_extensions()

        v = reg.validator_for("config.json")
        assert len(v.file_extensions()) == 0  # fallback
