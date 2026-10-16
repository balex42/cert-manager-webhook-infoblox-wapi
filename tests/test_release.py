"""Release safety regressions; Python standard library only (balex42 fork)."""

import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "workflow_scripts"))
import release
from oci_registry import Registry


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.version = release.scalar(Path(release.CHART, "Chart.yaml").read_text(), "version")

    def test_versions_must_match(self):
        release.validate_metadata(release.CHART, self.version)
        for version in ("99.98.97", "v3.0.6", "latest", "01.2.3", "3.0.6/path"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.validate_metadata(release.CHART, version)

    def test_tag_must_resolve_to_the_checked_out_commit(self):
        from argparse import Namespace

        args = Namespace(tag="v" + self.version, repository="balex42/cert-manager-webhook-infoblox-wapi")
        with patch.object(release, "run", side_effect=["tag-revision", "other-revision"]), self.assertRaises(ValueError):
            release.validate_release(args)

    def test_validated_release_exports_exact_revision(self):
        from argparse import Namespace

        args = Namespace(tag="v" + self.version, repository="balex42/cert-manager-webhook-infoblox-wapi")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "outputs"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(path)}), patch.object(release, "run", return_value="release-revision\n"):
                release.validate_release(args)
            outputs = path.read_text()
            self.assertIn("revision=release-revision\n", outputs)
            self.assertIn(f"version={self.version}\n", outputs)
            self.assertIn("chart_parent=balex42/charts\n", outputs)

    def test_package_pins_image_and_preserves_source(self):
        source = Path(release.CHART, "values.yaml").read_text()
        with tempfile.TemporaryDirectory() as temp:
            staged = Path(temp) / "chart"
            release.stage_chart(release.CHART, staged, self.version,
                                "ghcr.io/balex42/cert-manager-webhook-infoblox-wapi", "sha256:" + "a" * 64)
            values = (staged / "values.yaml").read_text()
            self.assertIn('digest: "sha256:' + "a" * 64 + '"', values)
            self.assertEqual((staged / "NOTICE").read_bytes(), Path("NOTICE").read_bytes())
            self.assertEqual((staged / "LICENSE").read_bytes(), Path("LICENSE").read_bytes())
        self.assertEqual(source, Path(release.CHART, "values.yaml").read_text())

    def test_invalid_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            release.stage_chart(release.CHART, Path(temp) / "chart", self.version, "ghcr.io/test/image", "latest")

    def test_archive_retries_ignore_timestamps_but_not_content(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = [Path(temp) / f"{i}.tgz" for i in range(3)]
            for index, path in enumerate(paths):
                data = b"same" if index < 2 else b"changed"
                with tarfile.open(path, "w:gz") as archive:
                    entry = tarfile.TarInfo("chart/values.yaml")
                    entry.size, entry.mtime = len(data), index
                    archive.addfile(entry, io.BytesIO(data))
            self.assertEqual(release.archive_contents(paths[0]), release.archive_contents(paths[1]))
            self.assertNotEqual(release.archive_contents(paths[0]), release.archive_contents(paths[2]))

    def test_registry_errors_are_not_missing_versions(self):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(int(self.path.rsplit("/", 1)[-1]))
                self.end_headers()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            registry = Registry(f"127.0.0.1:{server.server_port}", "test", plain_http=True)
            self.assertIsNone(registry.resolve("404"))
            for status in (401, 403, 500):
                with self.subTest(status=status), self.assertRaises(RuntimeError):
                    registry.resolve(str(status))
        finally:
            server.shutdown()
            worker.join()
            server.server_close()

    def test_existing_image_must_match_revision_and_platforms(self):
        registry = Registry("example.invalid", "test")
        labels = {
            "org.opencontainers.image.revision": "revision",
            "org.opencontainers.image.source": "source",
            "org.opencontainers.image.version": self.version,
        }
        documents = {
            "/manifests/index": {"manifests": [
                {"digest": arch, "platform": {"architecture": arch, "os": "linux"}}
                for arch in ("amd64", "arm64")
            ]},
            "/manifests/amd64": {"config": {"digest": "config"}},
            "/manifests/arm64": {"config": {"digest": "config"}},
            "/blobs/config": {"config": {"Labels": labels}},
        }
        with patch.object(registry, "document", side_effect=documents.__getitem__):
            registry.verify_image("index", "revision", "source", self.version)
            with self.assertRaises(RuntimeError):
                registry.verify_image("index", "different-revision", "source", self.version)
            documents["/manifests/index"]["manifests"].pop()
            with self.assertRaises(RuntimeError):
                registry.verify_image("index", "revision", "source", self.version)

    def test_bearer_authentication_for_new_package(self):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.headers.get("Authorization") == "Bearer test-token":
                    self.send_response(404)
                else:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", f'Bearer realm="http://127.0.0.1:{self.server.server_port}/token",service="registry",scope="repository:test:pull"')
                self.end_headers()

            def do_GET(self):
                observed.append((self.headers.get("Authorization"), urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"token": "test-token"}).encode())

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            with patch.dict(os.environ, {"REGISTRY_USERNAME": "user", "REGISTRY_PASSWORD": "pass"}):
                registry = Registry(f"127.0.0.1:{server.server_port}", "test", plain_http=True)
                self.assertIsNone(registry.resolve("new-version"))
            self.assertEqual(observed[0][0], "Basic dXNlcjpwYXNz")
            self.assertEqual(observed[0][1]["scope"], ["repository:test:pull,push"])
        finally:
            server.shutdown()
            worker.join()
            server.server_close()


@unittest.skipUnless(os.getenv("OCI_TEST_REGISTRY"), "Set OCI_TEST_REGISTRY for a local registry round-trip")
class OCIIntegrationTests(unittest.TestCase):
    def test_publish_pull_retry_and_conflict(self):
        from argparse import Namespace

        version = release.scalar(Path(release.CHART, "Chart.yaml").read_text(), "version")
        args = Namespace(registry=os.environ["OCI_TEST_REGISTRY"],
                         repository=f"test/charts-{uuid.uuid4().hex}/cert-manager-webhook-infoblox-wapi",
                         plain_http=True, version=version,
                         image="ghcr.io/balex42/cert-manager-webhook-infoblox-wapi",
                         digest="sha256:" + "a" * 64)
        release.run(sys.executable, "workflow_scripts/release.py", "chart", "--registry", args.registry,
                    "--repository", args.repository, "--version", args.version, "--image", args.image,
                    "--digest", args.digest, "--plain-http")
        registry = Registry(args.registry, args.repository, plain_http=True)
        original = registry.resolve(version)
        self.assertIsNotNone(original)
        release.publish_chart(args)  # Retry preserves the original manifest digest.
        self.assertEqual(original, registry.resolve(version))
        args.digest = "sha256:" + "b" * 64
        with self.assertRaises(RuntimeError):
            release.publish_chart(args)
        self.assertEqual(original, registry.resolve(version))


if __name__ == "__main__":
    unittest.main()
