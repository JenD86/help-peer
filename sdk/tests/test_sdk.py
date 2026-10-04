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

    def test_small_inputs_roundtrip(self):
        for n in range(1, 64):
            data = bytes(range(n))
            shards = erasure.encode_segment(data)
            shards[0] = None
            shards[7] = None
            assert erasure.decode_segment(shards, n) == data

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
        (tmp_path / "sub").mkdir()
        (tmp_path / "config.json").write_text("{}")
        (tmp_path / "sub" / "model.safetensors").write_text("weights")

        m, base = manifest.build_manifest(str(tmp_path), "test-transfer", 67108864)
        assert base == str(tmp_path)
        assert m.transfer_name == "test-transfer"
        assert m.version == 1
        assert [f.path for f in m.files] == ["config.json", "sub/model.safetensors"]
        assert m.total_bytes == 9

    def test_build_single_file(self, tmp_path):
        (tmp_path / "model.bin").write_bytes(b"abc")
        (tmp_path / "unrelated.txt").write_text("not sent")

        m, base = manifest.build_manifest(str(tmp_path / "model.bin"), "single", 67108864)
        assert base == str(tmp_path)
        assert [f.path for f in m.files] == ["model.bin"]
        assert m.total_bytes == 3

    def test_skips_symlinked_dirs(self, tmp_path):
        (tmp_path / "real").mkdir()
        (tmp_path / "real" / "w.bin").write_bytes(b"x")
        (tmp_path / "loop").symlink_to(tmp_path)
        (tmp_path / "link.bin").symlink_to(tmp_path / "real" / "w.bin")

        m, _ = manifest.build_manifest(str(tmp_path), "t", 64)
        assert [f.path for f in m.files] == ["link.bin", "real/w.bin"]

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
        assert restored.files[0].blake3 is None

    def test_json_roundtrip_with_file_hash(self):
        m = _valid_manifest()
        m.files[0].blake3 = "ab" * 32
        assert manifest.Manifest.from_json(m.to_json()).files[0].blake3 == "ab" * 32

    def test_validate_accepts_consistent_manifest(self):
        _valid_manifest().validate()

    @pytest.mark.parametrize("mutate", [
        lambda m: setattr(m, "total_bytes", 5),
        lambda m: setattr(m, "segment_size", 0),
        lambda m: setattr(m, "erasure_data_shards", 0),
        lambda m: m.files[0].segments.pop(),
        lambda m: setattr(m.files[0].segments[1], "original_size", 1),
        lambda m: setattr(m.files[0].segments[0], "encrypted_size", 1 << 40),
        lambda m: m.files[0].segments[0].shards.append(manifest.ManifestShard(12, "ab" * 32, "n")),
        lambda m: m.files[0].segments[0].shards.extend(
            [manifest.ManifestShard(1, "ab" * 32, "n"), manifest.ManifestShard(1, "ab" * 32, "n")]),
        lambda m: setattr(m.files[0], "blake3", "zz"),
    ])
    def test_validate_rejects_inconsistent_manifests(self, mutate):
        m = _valid_manifest()
        mutate(m)
        with pytest.raises(ValueError):
            m.validate()


def _valid_manifest():
    return manifest.Manifest(
        transfer_name="t", total_bytes=100, segment_size=64,
        files=[manifest.ManifestFile(path="a", size=100, segments=[
            manifest.ManifestSegment(id="seg_000000", original_size=64, encrypted_size=92),
            manifest.ManifestSegment(id="seg_000001", original_size=36, encrypted_size=64),
        ])],
    )


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


class TestTransferCode:
    def test_normalize_code(self):
        assert crypto.normalize_code(" Orbit  velvet-ZOOM ") == "orbit-velvet-zoom"
        assert crypto.derive_keys("Orbit Velvet") == crypto.derive_keys("orbit-velvet")

    def test_generate_code_format(self):
        from helppeer import client
        words = client._wordlist()
        assert len(words) == 7776
        code = client._generate_code()
        parts = code.split("-")
        assert len(parts) == client.CODE_WORDS
        assert all(p in words for p in parts)
        assert code != client._generate_code()


class TestSafeOutputPath:
    def test_accepts_nested(self):
        assert manifest.safe_output_path("/tmp/out", "sub/dir/model.safetensors") == \
            os.path.join("/tmp/out", "sub", "dir", "model.safetensors")

    @pytest.mark.parametrize("bad", [
        "", "../evil", "a/../../evil", "/etc/passwd", "a//b", "./a", "a/.",
        "..\\evil", "C:evil", "a\0b",
    ])
    def test_rejects_escapes(self, bad):
        with pytest.raises(ValueError):
            manifest.safe_output_path("/tmp/out", bad)


VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "protocol", "test-vectors.json")


@pytest.mark.skipif(not os.path.exists(VECTORS_PATH), reason="not running from the repo")
class TestSharedVectors:
    """Vectors shared with the Rust client and Go web backend."""

    def setup_method(self):
        with open(VECTORS_PATH) as f:
            self.v = json.load(f)

    def test_key_derivation(self):
        kd = self.v["key_derivation"]
        for code in [kd["code"], *kd["equivalent_inputs"]]:
            k_data, k_index = crypto.derive_keys(code)
            assert k_data.hex() == kd["k_data"]
            assert k_index.hex() == kd["k_index"]
            assert crypto.relay_hash(k_index) == kd["relay_hash"]

    def test_erasure(self):
        e = self.v["erasure"]
        data = bytes.fromhex(e["data"])
        shards = erasure.encode_segment(data, e["data_shards"], e["parity_shards"])
        assert [s.hex() for s in shards] == e["shards"]
        assert [crypto.content_hash(s) for s in shards] == e["shard_blake3"]

        # Rebuild from parity-heavy subsets
        for missing in ([0, 1, 2, 3], [4, 5, 6, 7], [1, 3, 8, 11]):
            partial = [bytes.fromhex(s) for s in e["shards"]]
            for i in missing:
                partial[i] = None
            assert erasure.decode_segment(partial, len(data)) == data
