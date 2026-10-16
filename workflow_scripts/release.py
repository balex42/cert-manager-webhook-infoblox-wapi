#!/usr/bin/env python3
"""Validate releases and publish immutable, digest-pinned OCI charts (balex42 fork).

Requires only Python's standard library and Helm. Files are staged outside the
source chart. Registry failures are never interpreted as an absent version.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from oci_registry import Registry


CHART = "charts/cert-manager-webhook-infoblox-wapi"
SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
DIGEST = r"sha256:[a-f0-9]{64}"


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture).stdout


def output(key, value):
    print(f"{key}={value}")
    if path := os.getenv("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"{key}={value}\n")


def scalar(text, key):
    # These release metadata fields are top-level scalars. Fail on unsupported
    # syntax instead of silently changing YAML structure or guessing a version.
    matches = re.findall(rf"^{re.escape(key)}: ([^#\n]+)", text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one top-level {key} field")
    return matches[0].strip().strip('\"\'')


def validate_metadata(chart, version):
    if not re.fullmatch(SEMVER, version):
        raise ValueError("Release version must be a semantic version without a v prefix")
    text = (Path(chart) / "Chart.yaml").read_text()
    if scalar(text, "version") != version or scalar(text, "appVersion") != version:
        raise ValueError("Release tag, Chart.yaml version, and appVersion must match")
    return scalar(text, "name")


def validate_release(args):
    if not args.tag.startswith("v"):
        raise ValueError("Release tag must use the vX.Y.Z format")
    version = args.tag[1:]
    validate_metadata(CHART, version)
    revision = run("git", "rev-parse", f"refs/tags/{args.tag}^{{commit}}", capture=True).strip()
    if revision != run("git", "rev-parse", "HEAD", capture=True).strip():
        raise ValueError("Checkout does not match the requested release tag")
    repository = args.repository.lower()
    output("version", version)
    output("revision", revision)
    output("image", f"ghcr.io/{repository}")
    output("chart_parent", f"{repository.split('/')[0]}/charts")


def check_image(args):
    registry = Registry(args.registry, args.repository, args.plain_http)
    digest = registry.resolve(args.version)
    if digest:
        registry.verify_image(digest, args.revision, args.source, args.version)
    output("digest", digest or "")


def stage_chart(source, destination, version, image, digest):
    if not re.fullmatch(DIGEST, digest):
        raise ValueError("Image must be pinned to a sha256 digest")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*", image):
        raise ValueError("Invalid image repository")
    name = validate_metadata(source, version)
    shutil.copytree(source, destination)
    values = destination / "values.yaml"
    text = values.read_text()
    match = re.search(r"^image:\n(?:[ \t].*\n|\n)*", text, re.MULTILINE)
    if match is None:
        raise ValueError("Expected an image section in values.yaml")
    block = match.group()
    for key, value in {"repository": image, "digest": digest, "tag": version}.items():
        block, count = re.subn(rf"^  {key}:.*$", f"  {key}: {json.dumps(value)}", block, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f"Expected exactly one image.{key} setting")
    values.write_text(text[:match.start()] + block + text[match.end():])
    root = Path(source).resolve().parents[1]
    for notice in ("LICENSE", "NOTICE"):
        shutil.copyfile(root / notice, destination / notice)
    return name


def archive_contents(path):
    with tarfile.open(path, "r:gz") as archive:
        # Ignore tar/gzip timestamps when comparing a release retry, not content.
        entries = {}
        for entry in archive:
            if entry.name in entries:
                raise ValueError("Chart archive contains duplicate paths")
            content = archive.extractfile(entry).read() if entry.isfile() else None
            entries[entry.name] = (entry.type, entry.mode, entry.linkname, content)
        return entries


def publish_chart(args):
    registry = Registry(args.registry, args.repository, args.plain_http)
    transport = ["--plain-http"] if args.plain_http else []
    with tempfile.TemporaryDirectory(prefix="infoblox-chart-") as temp:
        temp = Path(temp)
        staged = temp / "chart"
        name = stage_chart(CHART, staged, args.version, args.image, args.digest)
        if args.repository.split("/")[-1] != name:
            raise ValueError("OCI repository basename must match the chart name")
        run("helm", "lint", str(staged), "--strict", "--set", "infoblox.host=infoblox.example.com")
        run("helm", "package", str(staged), "--destination", str(temp))
        package = temp / f"{name}-{args.version}.tgz"
        reference = f"oci://{args.registry}/{args.repository}"
        existing = registry.resolve(args.version)
        if not existing:
            parent = args.repository.rsplit("/", 1)[0]
            run("helm", "push", str(package), f"oci://{args.registry}/{parent}", *transport)
        digest = registry.resolve(args.version)
        if not digest:
            raise RuntimeError("Chart version is missing after publication")
        pulled = temp / "pulled"
        pulled.mkdir()
        run("helm", "pull", f"{reference}@{digest}", "--destination", str(pulled), *transport)
        # Helm may name digest pulls after the digest rather than the chart version.
        archives = list(pulled.glob("*.tgz"))
        if len(archives) != 1:
            raise RuntimeError("Expected exactly one pulled chart archive")
        if archive_contents(package) != archive_contents(archives[0]):
            raise RuntimeError("Existing OCI chart differs from this release; refusing to overwrite")
        run("helm", "template", "release-check", str(archives[0]),
            "--set", "infoblox.host=infoblox.example.com", capture=True)
        output("digest", digest)
        output("chart", reference)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--tag", required=True)
    validate.add_argument("--repository", required=True)
    validate.set_defaults(handler=validate_release)
    for command, handler in (("image", check_image), ("chart", publish_chart)):
        sub = commands.add_parser(command)
        sub.add_argument("--registry", default="ghcr.io")
        sub.add_argument("--repository", required=True)
        sub.add_argument("--version", required=True)
        sub.add_argument("--plain-http", action="store_true", help="Only for local registry tests")
        if command == "image":
            sub.add_argument("--revision", required=True)
            sub.add_argument("--source", required=True)
        else:
            sub.add_argument("--image", required=True)
            sub.add_argument("--digest", required=True)
        sub.set_defaults(handler=handler)
    args = parser.parse_args()
    try:
        args.handler(args)
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release failed: {error}\n")


if __name__ == "__main__":
    main()
