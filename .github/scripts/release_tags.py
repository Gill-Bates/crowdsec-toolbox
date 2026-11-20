#!/usr/bin/env python3
#
# .github/scripts/release_tags.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

"""Create, verify and promote Docker Hub candidate tags for releases."""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ci_output import REPO_URL, log, print_header, write_outputs

__author__ = "Gill-Bates"
SCRIPT = Path(__file__).resolve()
HELP_URL = f"{REPO_URL}/blob/main/.github/scripts/{SCRIPT.name}"

TOOLS = ("abuse-reporter", "metrics-exporter")
ARCHES = ("amd64", "arm64")
VERSION_RE = re.compile(r"^([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$")
NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
DOCKERHUB_LOGIN_URL = "https://hub.docker.com/v2/users/login/"
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
REQUEST_TIMEOUT_SECONDS = 15
REQUEST_ATTEMPTS = 5
RETRY_DELAY_SECONDS = 2
MAX_TAG_PAGES = 10_000
INSPECT_FORMAT = "{{json .Manifest}}"
VersionKey = tuple[tuple[int, int, int], tuple[int, tuple[tuple[int, int, str], ...]]]


class _DockerHubRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        try:
            destination = urlsplit(new_url)
            port = destination.port
        except ValueError:
            return None
        if destination.scheme != "https" or destination.hostname != "hub.docker.com" or port not in (None, 443):
            return None
        return super().redirect_request(request, fp, code, message, headers, new_url)


_DOCKERHUB_OPENER = build_opener(_DockerHubRedirectHandler())


class ReleaseTagsError(Exception):
    """A release tag listing, candidate, or promotion could not be verified."""


def version_key(version: str) -> VersionKey | None:
    """Return the repository's sortable release key, or None for non-version tags."""
    match = VERSION_RE.fullmatch(version)
    if match is None:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    if len(release) == 2:
        release += (0,)
    suffix = match.group(2)
    if suffix is None:
        return release, (1, ())
    identifiers = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in suffix.split("."))
    return release, (0, identifiers)


def release_tag_key(tag: str) -> VersionKey | None:
    """Ignore moving, candidate and architecture tags when parsing releases."""
    for tool in TOOLS:
        prefix = f"{tool}-"
        if tag.startswith(prefix):
            version = tag.removeprefix(prefix)
            break
    else:
        return None
    if version == "latest" or version.rsplit("-", 1)[-1] in ARCHES:
        return None
    return version_key(version)


def _stable_release_tag_key(tag: str) -> VersionKey | None:
    """Return a key only for stable releases, which are the candidates for `latest`."""
    if any(tag.startswith(f"{tool}-") and "-" in tag.removeprefix(f"{tool}-") for tool in TOOLS):
        return None
    return release_tag_key(tag)


def newer_stable_release_tags(version: str, published_tags: list[str] | tuple[str, ...]) -> list[str]:
    """Return newer stable releases, which alone determine whether `latest` moves."""
    current = version_key(version)
    if current is None:
        raise ReleaseTagsError(f"unparseable release version: {version}")
    return sorted(
        tag for tag in set(published_tags) if (key := _stable_release_tag_key(tag)) is not None and key > current
    )


def _log_newest(version: str, newer: list[str]) -> None:
    if newer:
        log("info", f"Newer published release tags exist; {version} will not move -latest.")
    else:
        log("info", f"{version} is the newest published release.")


def candidate_tag(tool: str, run_id: str) -> str:
    if tool not in TOOLS:
        raise ReleaseTagsError(f"unsupported tool: {tool}")
    if not run_id.isdigit():
        raise ReleaseTagsError("GITHUB_RUN_ID must contain only digits")
    return f"{tool}-candidate-{run_id}"


def expected_manifest(digest_dir: Path, tool: str) -> dict[str, str]:
    if tool not in TOOLS:
        raise ReleaseTagsError(f"unsupported tool: {tool}")
    expected: dict[str, str] = {}
    for arch in ARCHES:
        path = digest_dir / f"{tool}-{arch}"
        try:
            digest = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ReleaseTagsError(f"digest artifact for {tool}/{arch} is missing") from exc
        if DIGEST_RE.fullmatch(digest) is None:
            raise ReleaseTagsError(f"digest artifact for {tool}/{arch} is invalid")
        expected[f"linux/{arch}"] = digest
    return expected


def parse_manifest_inspection(output: str) -> tuple[str, dict[str, str]]:
    """Parse imagetools index digest and the platform child digests it reports."""
    try:
        manifest = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ReleaseTagsError("registry index inspection returned invalid JSON") from exc
    if not isinstance(manifest, dict):
        raise ReleaseTagsError("registry index inspection did not return a manifest object")
    index_digest = manifest.get("digest")
    descriptors = manifest.get("manifests")
    if not isinstance(index_digest, str) or DIGEST_RE.fullmatch(index_digest) is None:
        raise ReleaseTagsError("registry index has no valid manifest digest")
    if not isinstance(descriptors, list):
        raise ReleaseTagsError("registry index has no manifest list")
    entries: dict[str, str] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise ReleaseTagsError("registry index returned a malformed manifest descriptor")
        platform = descriptor.get("platform")
        digest = descriptor.get("digest")
        if not isinstance(platform, dict) or not isinstance(digest, str):
            raise ReleaseTagsError("registry index returned a malformed platform entry")
        architecture = platform.get("architecture")
        operating_system = platform.get("os")
        if architecture == "unknown" and operating_system == "unknown":
            continue
        if not isinstance(architecture, str) or not isinstance(operating_system, str):
            raise ReleaseTagsError("registry index returned a malformed platform entry")
        platform_name = f"{operating_system}/{architecture}"
        if platform_name in entries:
            raise ReleaseTagsError(f"registry index contains duplicate platform {platform_name}")
        if DIGEST_RE.fullmatch(digest) is None:
            raise ReleaseTagsError(f"registry index contains an invalid digest for {platform_name}")
        entries[platform_name] = digest
    return index_digest, entries


def parse_push_digest(output: str) -> str:
    """Extract the digest reported after Docker successfully pushes an image."""
    matches = re.findall(r"^[^\r\n]*digest: (sha256:[0-9a-f]{64})(?:\s|$)", output, re.MULTILINE)
    if len(set(matches)) != 1:
        raise ReleaseTagsError("Docker push output did not report one image digest")
    return matches[0]


def verify_manifest(expected: dict[str, str], actual: dict[str, str], reference: str) -> None:
    if actual != expected:
        expected_text = ", ".join(f"{key}={value}" for key, value in sorted(expected.items()))
        actual_text = ", ".join(f"{key}={value}" for key, value in sorted(actual.items())) or "none"
        raise ReleaseTagsError(
            f"candidate {reference} does not match the build digests: {actual_text} != {expected_text}"
        )


def docker_command(arguments: list[str], *, input_text: str | None = None, timeout: int = 180) -> str:
    try:
        result = subprocess.run(
            ["docker", *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseTagsError(f"Docker command failed ({exc.__class__.__name__})") from exc
    if result.returncode != 0:
        raise ReleaseTagsError(f"Docker command failed with exit code {result.returncode}")
    return result.stdout.strip()


def inspect_manifest(reference: str) -> tuple[str, dict[str, str]]:
    output = docker_command(["buildx", "imagetools", "inspect", reference, "--format", INSPECT_FORMAT])
    return parse_manifest_inspection(output)


def tag_manifest(image: str, tag: str, digest: str) -> None:
    docker_command(["buildx", "imagetools", "create", "--tag", f"{image}:{tag}", f"{image}@{digest}"])


def create_candidate(image: str, tool: str, version: str, run_id: str, digest_dir: Path) -> str:
    expected = expected_manifest(digest_dir, tool)
    if version_key(version) is None:
        raise ReleaseTagsError(f"unparseable release version: {version}")
    tag = candidate_tag(tool, run_id)
    reference = f"{image}:{tag}"
    sources = [f"{image}@{expected[f'linux/{arch}']}" for arch in ARCHES]
    docker_command(["buildx", "imagetools", "create", "--tag", reference, *sources])
    index_digest, actual = inspect_manifest(reference)
    verify_manifest(expected, actual, reference)
    log("info", f"Created and verified candidate {tag} ({index_digest}).")
    return index_digest


def _request_json(
    url: str,
    *,
    headers: dict[str, str],
    body: bytes | None = None,
    attempts: int = REQUEST_ATTEMPTS,
) -> tuple[int, dict[str, Any] | None]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ReleaseTagsError("Docker Hub API URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "hub.docker.com"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        raise ReleaseTagsError("Docker Hub API URL is not an approved HTTPS endpoint")
    request = Request(url, data=body, headers=headers)  # noqa: S310 URL was restricted to HTTPS hub.docker.com above
    for attempt in range(attempts):
        try:
            with _DOCKERHUB_OPENER.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                try:
                    payload = json.loads(response.read())
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ReleaseTagsError("Docker Hub API returned invalid JSON") from exc
                return response.status, payload if isinstance(payload, dict) else None
        except HTTPError as exc:
            if exc.code == 404:
                return exc.code, None
            if exc.code not in RETRYABLE_STATUS or attempt == attempts - 1:
                raise ReleaseTagsError(f"Docker Hub API returned HTTP {exc.code}") from exc
        except (OSError, TimeoutError, URLError) as exc:
            if attempt == attempts - 1:
                raise ReleaseTagsError(f"Docker Hub API request failed ({exc.__class__.__name__})") from exc
        time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
    raise ReleaseTagsError("Docker Hub API request exhausted retries")


def dockerhub_token(username: str, password: str) -> str:
    if NAMESPACE_RE.fullmatch(username) is None or not password:
        raise ReleaseTagsError("Docker Hub credentials are missing or malformed")
    status, login = _request_json(
        DOCKERHUB_LOGIN_URL,
        headers={"Content-Type": "application/json"},
        body=json.dumps({"username": username, "password": password}).encode("utf-8"),
        attempts=1,
    )
    token = login.get("token") or login.get("access_token") if login else None
    if status != 200 or not isinstance(token, str) or not token:
        raise ReleaseTagsError(f"Docker Hub login failed (HTTP {status})")
    return token


def tag_exists(username: str, token: str, tag: str) -> bool:
    """Direct tag lookup; 404 means the tag is free, any other failure raises (fail closed)."""
    if NAMESPACE_RE.fullmatch(username) is None or TAG_RE.fullmatch(tag) is None:
        raise ReleaseTagsError("Docker Hub tag lookup got a malformed namespace or tag")
    url = f"https://hub.docker.com/v2/namespaces/{username}/repositories/crowdsec-toolbox/tags/{tag}"
    status, payload = _request_json(url, headers={"Authorization": f"Bearer {token}"})
    if status == 404:
        return False
    if status != 200 or payload is None:
        raise ReleaseTagsError(f"Docker Hub tag lookup for {tag} failed (HTTP {status})")
    return True


def list_published_tags(username: str, password: str, *, allow_empty: bool) -> list[str]:
    token = dockerhub_token(username, password)

    base = f"https://hub.docker.com/v2/namespaces/{username}/repositories/crowdsec-toolbox/tags"
    next_url = f"{base}?page_size=100"
    visited: set[str] = set()
    tags: list[str] = []
    first_page = True
    while next_url:
        parsed = urlsplit(next_url)
        if parsed.scheme != "https" or parsed.netloc != "hub.docker.com" or parsed.path != urlsplit(base).path:
            raise ReleaseTagsError("Docker Hub returned an unexpected pagination URL")
        if next_url in visited or len(visited) >= MAX_TAG_PAGES:
            raise ReleaseTagsError("Docker Hub tag listing pagination did not finish")
        visited.add(next_url)
        status, page = _request_json(next_url, headers={"Authorization": f"Bearer {token}"})
        if status == 404 and first_page and allow_empty:
            log("info", "No Docker Hub repository exists yet; treating this as the first release.")
            return []
        if status != 200 or page is None:
            raise ReleaseTagsError(f"Docker Hub tag listing failed (HTTP {status})")
        results = page.get("results")
        if not isinstance(results, list):
            raise ReleaseTagsError("Docker Hub tag listing has no results array")
        for result in results:
            if not isinstance(result, dict) or not isinstance(result.get("name"), str):
                raise ReleaseTagsError("Docker Hub returned a malformed tag entry")
            tags.append(result["name"])
        page_next = page.get("next")
        if page_next in (None, "", "null"):
            next_url = ""
        elif isinstance(page_next, str):
            next_url = page_next
        else:
            raise ReleaseTagsError("Docker Hub returned a malformed pagination cursor")
        first_page = False
    return tags


def publish_verified_version_tag(
    image: str,
    tool: str,
    version: str,
    candidate_digest: str,
    expected: dict[str, str],
    *,
    already_published: bool,
    exists: Callable[[str], bool],
    inspect: Callable[[str], tuple[str, dict[str, str]]],
    tag: Callable[[str, str, str], None],
) -> None:
    if version_key(version) is None or DIGEST_RE.fullmatch(candidate_digest) is None:
        raise ReleaseTagsError("cannot promote an invalid release version or candidate digest")

    version_tag = f"{tool}-{version}"
    reference = f"{image}:{version_tag}"
    # The tag list may be stale; a direct lookup right before the write decides.
    if already_published or exists(version_tag):
        verify_existing_version_tag(image, version_tag, candidate_digest, expected, inspect)
        log("info", f"Version tag {version_tag} already references the verified candidate digest.")
        return

    tag(image, version_tag, candidate_digest)
    published_digest, published_entries = inspect(reference)
    verify_manifest(expected, published_entries, reference)
    if published_digest != candidate_digest:
        raise ReleaseTagsError(f"version tag {version_tag} does not reference the verified candidate digest")
    log("info", f"Promoted verified candidate to {version_tag}.")


def verify_existing_version_tag(
    image: str,
    version_tag: str,
    candidate_digest: str,
    expected: dict[str, str],
    inspect: Callable[[str], tuple[str, dict[str, str]]],
) -> None:
    reference = f"{image}:{version_tag}"
    published_digest, published_entries = inspect(reference)
    verify_manifest(expected, published_entries, reference)
    if published_digest != candidate_digest:
        raise ReleaseTagsError(f"version tag {version_tag} already points to a different digest")


def publish_latest_tag(
    image: str,
    tool: str,
    candidate_digest: str,
    expected: dict[str, str],
    *,
    inspect: Callable[[str], tuple[str, dict[str, str]]],
    tag: Callable[[str, str, str], None],
) -> None:
    latest_tag = f"{tool}-latest"
    tag(image, latest_tag, candidate_digest)
    latest_digest, latest_entries = inspect(f"{image}:{latest_tag}")
    verify_manifest(expected, latest_entries, f"{image}:{latest_tag}")
    if latest_digest != candidate_digest:
        raise ReleaseTagsError(f"latest tag {latest_tag} does not reference the verified candidate digest")
    log("info", f"Moved {latest_tag} to the verified candidate.")


def verify_candidates(
    image: str,
    run_id: str,
    expected_by_tool: dict[str, dict[str, str]],
    inspect: Callable[[str], tuple[str, dict[str, str]]],
) -> dict[str, str]:
    digests: dict[str, str] = {}
    for tool in TOOLS:
        reference = f"{image}:{candidate_tag(tool, run_id)}"
        digest, actual = inspect(reference)
        verify_manifest(expected_by_tool[tool], actual, reference)
        digests[tool] = digest
        log("info", f"Verified candidate index for {tool} ({digest}).")
    return digests


def promote_release(
    image: str,
    version: str,
    run_id: str,
    digest_dir: Path,
    list_tags: Callable[[], list[str]],
    inspect: Callable[[str], tuple[str, dict[str, str]]],
    tag: Callable[[str, str, str], None],
    exists: Callable[[str], bool],
) -> bool:
    """Verify every candidate, refresh registry state, then publish public tags."""
    if version_key(version) is None:
        raise ReleaseTagsError(f"unparseable release version: {version}")
    expected_by_tool = {tool: expected_manifest(digest_dir, tool) for tool in TOOLS}
    initial_candidate_digests = verify_candidates(image, run_id, expected_by_tool, inspect)

    published_tags = list_tags()
    newer = newer_stable_release_tags(version, published_tags)
    is_newest = not newer
    candidate_digests = verify_candidates(image, run_id, expected_by_tool, inspect)
    if candidate_digests != initial_candidate_digests:
        raise ReleaseTagsError("candidate indexes changed while re-reading the Docker Hub release list")
    _log_newest(version, newer)

    existing_version_tags = {tool: f"{tool}-{version}" in published_tags for tool in TOOLS}
    for tool in TOOLS:
        if existing_version_tags[tool]:
            verify_existing_version_tag(
                image,
                f"{tool}-{version}",
                candidate_digests[tool],
                expected_by_tool[tool],
                inspect,
            )

    for tool in TOOLS:
        publish_verified_version_tag(
            image,
            tool,
            version,
            candidate_digests[tool],
            expected_by_tool[tool],
            already_published=existing_version_tags[tool],
            exists=exists,
            inspect=inspect,
            tag=tag,
        )
    if "-" not in version and is_newest:
        for tool in TOOLS:
            publish_latest_tag(
                image,
                tool,
                candidate_digests[tool],
                expected_by_tool[tool],
                inspect=inspect,
                tag=tag,
            )
    elif "-" in version:
        log("info", f"Skipped latest tags for prerelease {version}.")
    else:
        log("info", "Skipped latest tags because a newer release exists.")
    return is_newest


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ReleaseTagsError(f"missing required environment variable {name}")
    return value


def run_newest() -> int:
    version = _require_env("VERSION")
    username = _require_env("DOCKERHUB_USERNAME")
    password = _require_env("DOCKERHUB_TOKEN")
    published = list_published_tags(username, password, allow_empty=True)
    newer = newer_stable_release_tags(version, published)
    is_newest = not newer
    _log_newest(version, newer)
    write_outputs({"is_newest": str(is_newest).lower()})
    return 0


def run_record_pushed_digest() -> int:
    push_output_file = Path(_require_env("PUSH_OUTPUT_FILE"))
    digest_file = Path(_require_env("DIGEST_FILE"))
    try:
        output = push_output_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseTagsError("Docker push output is missing") from exc
    digest = parse_push_digest(output)
    digest_file.parent.mkdir(parents=True, exist_ok=True)
    digest_file.write_text(digest, encoding="utf-8")
    log("info", f"Recorded the successful push digest {digest}.")
    return 0


def run_promote() -> int:
    version = _require_env("VERSION")
    run_id = _require_env("RUN_ID")
    username = _require_env("DOCKERHUB_USERNAME")
    password = _require_env("DOCKERHUB_TOKEN")
    image = _require_env("IMAGE_NAME")
    digest_dir = Path(_require_env("DIGEST_DIR"))
    current_hint = os.environ.get("META_IS_NEWEST")
    for tool in TOOLS:
        expected_manifest(digest_dir, tool)
        candidate_tag(tool, run_id)

    try:
        login = subprocess.run(
            ["docker", "login", "--username", username, "--password-stdin"],
            input=f"{password}\n",
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseTagsError(f"Docker Hub login failed ({exc.__class__.__name__})") from exc
    if login.returncode != 0:
        raise ReleaseTagsError(f"Docker Hub login failed with exit code {login.returncode}")

    try:
        token = dockerhub_token(username, password)
        is_newest = promote_release(
            image,
            version,
            run_id,
            digest_dir,
            lambda: list_published_tags(username, password, allow_empty=False),
            inspect_manifest,
            tag_manifest,
            lambda name: tag_exists(username, token, name),
        )
        if current_hint in {"true", "false"} and (current_hint == "true") != is_newest:
            log("warning", "Docker Hub release state changed since the metadata preflight; using this fresh listing.")
        return 0
    finally:
        try:
            logout = subprocess.run(
                ["docker", "logout", "docker.io"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except OSError, subprocess.SubprocessError:
            log("warning", "Docker Hub logout could not complete.")
        else:
            if logout.returncode != 0:
                log("warning", "Docker Hub logout returned a non-zero status.")


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)
    description = (__doc__ or "").strip().splitlines()[0]
    print_header(SCRIPT, description, __author__, HELP_URL)
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("command", choices=("newest", "create-candidate", "promote", "record-pushed-digest"))
    args = parser.parse_args(argv)
    try:
        if args.command == "newest":
            return run_newest()
        if args.command == "create-candidate":
            create_candidate(
                _require_env("IMAGE_NAME"),
                _require_env("TOOL"),
                _require_env("VERSION"),
                _require_env("RUN_ID"),
                Path(_require_env("DIGEST_DIR")),
            )
            return 0
        if args.command == "record-pushed-digest":
            return run_record_pushed_digest()
        return run_promote()
    except ReleaseTagsError as exc:
        log("error", str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
