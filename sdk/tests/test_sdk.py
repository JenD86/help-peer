"""Tests for Help Peer SDK."""
import os
import json
import struct
import tempfile
import shutil
import pytest

import requests

from helppeer import client, crypto, erasure, manifest, nodes, validator
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

    def test_blocked_media_single_file(self, tmp_path):
        (tmp_path / "photo.jpg").write_bytes(b"img")

        with pytest.raises(ValueError, match="media files"):
            manifest.build_manifest(str(tmp_path / "photo.jpg"), "t", 67108864)

    def test_blocked_media_in_dir_is_skipped(self, tmp_path):
        (tmp_path / "model.safetensors").write_bytes(b"weights")
        (tmp_path / "song.mp3").write_bytes(b"audio")
        (tmp_path / "clip.mp4").write_bytes(b"video")

        m, _ = manifest.build_manifest(str(tmp_path), "t", 67108864)
        assert [f.path for f in m.files] == ["model.safetensors"]

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
        lambda m: m.files[0].segments[0].shards.append(manifest.ManifestShard(0, "ab" * 32, "file:///etc/passwd")),
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


@pytest.fixture
def local_server():
    """A local HTTP server: /shard/small returns 10 bytes, /shard/big 1 MB,
    /shard/redirect redirects to /shard/small."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/shard/redirect":
                self.send_response(302)
                self.send_header("Location", "/shard/small")
                self.end_headers()
                return
            body = b"x" * (10 if self.path == "/shard/small" else 1 << 20)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionError:
                pass  # the client stopped reading an oversized body, as it should

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


class TestNodes:
    def test_public_ips(self):
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"]:
            assert nodes.is_public_ip(ip), ip
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                   "0.0.0.0", "255.255.255.255", "224.0.0.1", "240.0.0.1", "192.0.2.1", "198.18.0.1",
                   "::1", "::", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
                   "64:ff9b::a00:1", "::127.0.0.1", "2001:db8::1", "not an ip"]:
            assert not nodes.is_public_ip(ip), ip

    def test_check_node_url(self):
        for ok in ["https://node.example.com", "http://1.2.3.4:7001", "https://example.com/node1"]:
            nodes.check_node_url(ok)
        for bad in ["", "n", None, "file:///etc/passwd", "ftp://example.com", "https://user:pw@example.com",
                    "https://example.com?x=1", "https://example.com#x", "http://example.com:99999"]:
            with pytest.raises(ValueError):
                nodes.check_node_url(bad)

    def test_configured_nodes_are_trusted(self):
        ns = nodes.NodeSessions(["http://127.0.0.1:7001", "https://Node.example.com/"], "trusted", "public")
        assert ns.for_node("http://127.0.0.1:7001") == "trusted"
        assert ns.for_node("https://node.example.com:443") == "trusted"
        assert ns.for_node("http://127.0.0.1:7002") == "public"
        assert ns.for_node("http://node.example.com") == "public"

    def test_public_session_refuses_private_addresses(self, local_server):
        public = client._public_session()
        for url in [local_server, local_server.replace("127.0.0.1", "localhost")]:
            with pytest.raises(requests.ConnectionError, match="not a public address"):
                client._get_limited(public, url + "/shard/small", 100)

    def test_trusted_node_works_without_redirects_or_oversized_bodies(self, local_server):
        session = client._session()
        assert client._get_limited(session, local_server + "/shard/small", 100) == (200, b"x" * 10)
        assert client._get_limited(session, local_server + "/shard/redirect", 100) == (302, None)
        with pytest.raises(ValueError, match="larger than"):
            client._get_limited(session, local_server + "/shard/big", 1000)

    def test_download_shards_from_untrusted_private_node_fails_clearly(self, local_server):
        from concurrent.futures import ThreadPoolExecutor
        seg = manifest.ManifestSegment(id="seg_000000", original_size=10, encrypted_size=38, shards=[
            manifest.ManifestShard(i, "ab" * 32, local_server) for i in range(12)])
        ns = nodes.NodeSessions([], client._session(), client._public_session())
        with ThreadPoolExecutor(4) as pool, pytest.raises(RuntimeError, match="private or internal address"):
            client._download_shards(ns, pool, seg, 8, 4)


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

    def test_shard_delete_tokens(self):
        st = self.v["shard_delete_tokens"]
        assert st["context"] == crypto.SHARD_DELETE_KEY_CONTEXT
        key = crypto.shard_delete_key(st["delete_token"])
        assert key.hex() == st["shard_delete_key"]
        for s in st["shards"]:
            token = crypto.shard_token(key, s["shard_hash"])
            assert token == s["shard_token"]
            assert crypto.secret_hash(token) == s["shard_token_hash"]

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


class TestSendToRecipients:
    def test_requires_username_before_uploading(self, tmp_path, monkeypatch):
        class Api:
            def whoami(self):
                return {"email": "a@example.com", "username": ""}

        monkeypatch.setattr(client, "current_api", lambda: Api())
        monkeypatch.setattr(client, "resolve_servers", lambda: pytest.fail("uploaded before checking"))
        (tmp_path / "f.bin").write_bytes(b"x")
        with pytest.raises(RuntimeError, match="username"):
            client.send(str(tmp_path / "f.bin"), to=["bob"])



class TestLoggedInSideEffects:
    def test_receipt_only_for_inbox_items(self):
        class Api:
            marked = []

            def inbox(self):
                return [{"manifest_hash": "in-inbox"}]

            def mark_received(self, h):
                self.marked.append(h)

        api = Api()
        client._clear_from_inbox(api, "not-from-this-site")
        client._clear_from_inbox(api, "in-inbox")
        assert api.marked == ["in-inbox"]

    def test_website_nodes_are_not_trusted(self, monkeypatch):
        from helppeer import config

        class Api:
            def server_config(self):
                return {"relay_url": "https://relay.site", "storage_nodes": ["http://169.254.169.254"]}

        monkeypatch.setattr(config, "_default_config", config.Config(relay_url=None, storage_nodes=None))
        monkeypatch.setattr("helppeer.account.current_api", lambda: Api())
        assert config.resolve_servers()[1] == ["http://169.254.169.254"]  # still used...
        assert config.trusted_nodes() == config.DEFAULT_NODES  # ...but not trusted
        monkeypatch.setattr(config, "_default_config", config.Config(storage_nodes=["http://10.0.0.5:7001"]))
        assert config.trusted_nodes() == ["http://10.0.0.5:7001"]



class TestShardDeleteTokens:
    def test_old_manifests_use_the_shared_token(self):
        m = _valid_manifest()
        m2 = manifest.Manifest.from_json(m.to_json())
        assert m2.shard_delete_tokens is False and b"shard_delete_tokens" not in m.to_json()
        assert client._shard_delete_token(m2, "ab" * 32) == m2.delete_token

    def test_new_manifests_use_per_shard_tokens(self):
        m = _valid_manifest()
        m.shard_delete_tokens = True
        m2 = manifest.Manifest.from_json(m.to_json())
        assert m2.shard_delete_tokens is True
        a, b = client._shard_delete_token(m2, "ab" * 32), client._shard_delete_token(m2, "cd" * 32)
        assert a != b and a != m2.delete_token
        assert a == crypto.shard_token(crypto.shard_delete_key(m2.delete_token), "ab" * 32)



class TestSlowUploads:
    def test_upload_slower_than_connect_timeout(self, monkeypatch):
        """A body that takes longer to send than the connect timeout must still
        upload: the timeout applies per block, not to the whole body."""
        import threading, time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class SlowReader(BaseHTTPRequestHandler):
            def do_PUT(self):
                left = int(self.headers["Content-Length"])
                while left:  # read about 4 MB/s
                    chunk = self.rfile.read(min(left, 256 * 1024))
                    left -= len(chunk)
                    time.sleep(0.06)
                self.send_response(201)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowReader)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        node = f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setattr(client, "TIMEOUT", (0.3, 30))
        try:
            data = os.urandom(8 * 1024 * 1024)  # ~2 s to read, far more than 0.3 s
            uploader = client._ShardUploader([node], crypto.shard_delete_key("ab" * 32))
            shard = uploader.upload(client._session(), 0, data)
            assert shard.node == node
        finally:
            server.shutdown()
