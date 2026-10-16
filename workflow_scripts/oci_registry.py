"""Small read-only Registry v2 client used by release checks (balex42 fork)."""

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


class Registry:
    def __init__(self, host, repository, plain_http=False):
        self.base = f"{'http' if plain_http else 'https'}://{host}/v2/{repository}"
        self.plain_http = plain_http
        self.token = None

    def request(self, path, method="GET", missing_ok=False):
        headers = {
            "Accept": ", ".join([
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ])
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base + path, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.headers, response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None
            challenge = error.headers.get("WWW-Authenticate", "")
            if error.code != 401 or self.token or not challenge.lower().startswith("bearer "):
                raise RuntimeError(f"Registry {method} failed: HTTP {error.code}") from None
            self.authenticate(challenge)
            return self.request(path, method, missing_ok)
        except urllib.error.URLError as error:
            raise RuntimeError(f"Registry connection failed: {error.reason}") from None

    def authenticate(self, challenge):
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.get("realm", "")
        if urllib.parse.urlparse(realm).scheme != "https" and not self.plain_http:
            raise RuntimeError("Registry token endpoint must use HTTPS")
        headers = {}
        username, password = os.getenv("REGISTRY_USERNAME"), os.getenv("REGISTRY_PASSWORD")
        if username and password:
            # Publishing credentials also need create permission for a package
            # that does not exist yet. Reads still fail on any authorization error.
            if fields.get("scope", "").startswith("repository:"):
                repository = fields["scope"].rsplit(":", 1)[0]
                fields["scope"] = repository + ":pull,push"
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        query = urllib.parse.urlencode({key: fields[key] for key in ("service", "scope") if key in fields})
        request = urllib.request.Request(realm + ("&" if "?" in realm else "?") + query, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.load(response)
        except urllib.error.URLError:
            raise RuntimeError("Registry authentication failed") from None
        self.token = data.get("token") or data.get("access_token")
        if not self.token:
            raise RuntimeError("Registry did not return an access token")

    def resolve(self, reference):
        response = self.request(f"/manifests/{reference}", method="HEAD", missing_ok=True)
        if response is None:
            return None
        digest = response[0].get("Docker-Content-Digest", "")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise RuntimeError("Registry returned an invalid manifest digest")
        return digest

    def document(self, path):
        return json.loads(self.request(path)[1])

    def verify_image(self, digest, revision, source, version):
        index = self.document(f"/manifests/{digest}")
        platforms = {
            entry.get("platform", {}).get("architecture"): entry["digest"]
            for entry in index.get("manifests", [])
            if entry.get("platform", {}).get("os") == "linux"
        }
        if not {"amd64", "arm64"}.issubset(platforms):
            raise RuntimeError("Existing release image must contain linux/amd64 and linux/arm64")
        expected = {
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.source": source,
            "org.opencontainers.image.version": version,
        }
        for architecture in ("amd64", "arm64"):
            manifest = self.document(f"/manifests/{platforms[architecture]}")
            config = self.document(f"/blobs/{manifest['config']['digest']}")
            labels = config.get("config", {}).get("Labels", {})
            if any(labels.get(key) != value for key, value in expected.items()):
                raise RuntimeError("Existing image version belongs to different release metadata; refusing to overwrite")
