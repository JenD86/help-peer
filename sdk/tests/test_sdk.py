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
        assert m.version == manifest.MANIFEST_VERSION
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
        lambda m: setattr(m, "version", 1),
        lambda m: setattr(m, "ack_secret", ""),
        lambda m: setattr(m, "delete_token", "x"),
    ])
    def test_validate_rejects_inconsistent_manifests(self, mutate):
        m = _valid_manifest()
        mutate(m)
        with pytest.raises(ValueError):
            m.validate()


def _valid_manifest():
    return manifest.Manifest(
        transfer_name="t", total_bytes=100, segment_size=64,
        ack_secret="cd" * 32, delete_token="ef" * 32,
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

    def test_secret_hash(self):
        sh = self.v["secret_hash"]
        assert crypto.secret_hash(sh["secret"]) == sh["blake3"]

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


class TestResumeLog:
    def test_records_survive_reopen(self, tmp_path):
        from helppeer.resume import ResumeLog
        log = ResumeLog(str(tmp_path), "abc")
        assert log.previously_done == 0
        log.record("a/b.bin", 0, "h0")
        log.record("a/b.bin", 2, "h2")
        log.close()

        log = ResumeLog(str(tmp_path), "abc")
        assert log.previously_done == 2
        assert log.completed("a/b.bin", 2) == "h2"
        assert log.completed("a/b.bin", 1) is None
        log.remove()
        assert not (tmp_path / ".helppeer").exists()

    def test_other_manifest_starts_fresh(self, tmp_path):
        from helppeer.resume import ResumeLog
        log = ResumeLog(str(tmp_path), "abc")
        log.record("f", 0, "h")
        log.close()
        os.rename(tmp_path / ".helppeer" / "abc.partial", tmp_path / ".helppeer" / "def.partial")
        assert ResumeLog(str(tmp_path), "def").previously_done == 0

    def test_reads_rust_format_and_skips_truncated_line(self, tmp_path):
        from helppeer.resume import ResumeLog
        state = tmp_path / ".helppeer"
        state.mkdir()
        # Exactly what the Rust client writes (serde_json, no spaces), with a
        # final line cut short by a killed process.
        (state / "m.partial").write_text(
            '{"version":1,"manifest_id":"m"}\n'
            '{"file":"f","segment":0,"blake3":"h"}\n'
            '{"file":"f","segm'
        )
        log = ResumeLog(str(tmp_path), "m")
        assert log.previously_done == 1
        log.record("f", 1, "h1")
        log.close()
        assert ResumeLog(str(tmp_path), "m").previously_done == 2


class TestAccount:
    def test_is_email(self):
        from helppeer.account import is_email
        assert is_email("a@b.com")
        assert not is_email("@alice")
        assert not is_email("alice")

    def test_login_saves_private_config_and_logout_removes_it(self, tmp_path, monkeypatch):
        from helppeer import account
        monkeypatch.setenv("HELPEER_CONFIG", str(tmp_path / "cfg" / "config.json"))
        monkeypatch.setattr(account.Api, "whoami", lambda self: {"email": "a@b.com", "username": "a"})

        result = account.login("https://hp.example.com/", "hp_secret")
        assert result["server"] == "https://hp.example.com"
        assert account.load_login() == {"server": "https://hp.example.com", "token": "hp_secret"}
        assert os.stat(result["config"]).st_mode & 0o777 == 0o600

        assert account.logout() is True
        assert account.load_login() is None
        assert account.logout() is False


class TestServerResolution:
    def _set(self, monkeypatch, relay, nodes, server_cfg):
        from helppeer import config, account
        monkeypatch.setattr(config, "_default_config", config.Config(relay_url=relay, storage_nodes=nodes))
        api = None
        if server_cfg is not None:
            api = type("FakeApi", (), {"server_config": lambda self: server_cfg})()
        monkeypatch.setattr(account, "current_api", lambda: api)

    def test_explicit_settings_win(self, monkeypatch):
        from helppeer.config import resolve_servers
        self._set(monkeypatch, "http://r:1", ["http://n:1"], {"relay_url": "http://site-relay", "storage_nodes": ["x"]})
        assert resolve_servers() == ("http://r:1", ["http://n:1"])

    def test_logged_in_site_fills_gaps(self, monkeypatch):
        from helppeer.config import resolve_servers
        self._set(monkeypatch, None, None, {"relay_url": "https://relay.site/", "storage_nodes": ["https://n1", "https://n2"]})
        assert resolve_servers() == ("https://relay.site", ["https://n1", "https://n2"])

    def test_defaults_when_not_logged_in(self, monkeypatch):
        from helppeer.config import resolve_servers, DEFAULT_RELAY, DEFAULT_NODES
        self._set(monkeypatch, None, None, None)
        assert resolve_servers() == (DEFAULT_RELAY, DEFAULT_NODES)


class TestCLIParsing:
    def test_global_options_work_before_or_after_subcommand(self):
        from helppeer.cli import build_parser
        p = build_parser()
        a = p.parse_args(["--json", "--relay", "http://r", "receive", "code"])
        assert (a.json, a.relay, a.nodes) == (True, "http://r", None)
        a = p.parse_args(["receive", "code", "--json", "--nodes", "http://n1,http://n2"])
        assert (a.json, a.relay, a.nodes) == (True, None, "http://n1,http://n2")
        # A value given before the subcommand isn't reset by the subcommand's copy.
        a = p.parse_args(["--relay", "http://r", "send", "./x"])
        assert a.relay == "http://r" and a.json is False


class TestMessage:
    def test_message_roundtrips_in_manifest(self):
        m = _valid_manifest()
        m.message = "Fine-tuned on run 42.\nUse with tokenizer v3."
        assert manifest.Manifest.from_json(m.to_json()).message == m.message
        m.validate()

    def test_manifest_without_message(self):
        m = _valid_manifest()
        assert "message" not in json.loads(m.to_json())
        assert manifest.Manifest.from_json(m.to_json()).message is None

    def test_too_long_message_rejected(self):
        m = _valid_manifest()
        m.message = "x" * (manifest.MAX_MESSAGE_CHARS + 1)
        with pytest.raises(ValueError):
            m.validate()

    def test_send_rejects_long_message_before_uploading(self, tmp_path):
        import helppeer
        (tmp_path / "f").write_text("x")
        with pytest.raises(ValueError, match="longer than"):
            helppeer.send(str(tmp_path / "f"), message="x" * 2001)

    def test_printable_strips_escape_sequences(self):
        assert manifest.printable("hi\x1b[2Jthere\nline 2\ttab\x07") == "hi[2Jthere\nline 2\ttab"
