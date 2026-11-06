"""Resolve the pinned Probe binary (`autofix`): cached, else downloaded and checksum-verified."""

from __future__ import annotations

import hashlib
import platform
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

RELEASE_URL = 'https://github.com/trustabl/agent-network-access-probe/releases/download'


def platform_asset(version: str) -> tuple[str, str]:
    """Return the release asset name and the binary name inside it.

    Windows ARM64 takes the amd64 build, which runs under emulation; there is
    no native windows/arm64 asset.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ('x86_64', 'amd64'):
        arch = 'amd64'
    elif machine in ('aarch64', 'arm64'):
        arch = 'arm64'
    else:
        raise RuntimeError(f'Unsupported architecture: {platform.machine()}')

    if system == 'windows':
        arch = 'amd64'  # ponytail: no native windows/arm64 build; emulation works
        return f'autofix_{version}_windows_{arch}.zip', 'autofix.exe'
    if system == 'darwin':
        return f'autofix_{version}_darwin_{arch}.tar.gz', 'autofix'
    if system == 'linux':
        return f'autofix_{version}_linux_{arch}.tar.gz', 'autofix'
    raise RuntimeError(f'Unsupported platform: {platform.system()}')


def cache_dir(version: str) -> Path:
    """Where a verified Probe of this version is kept: the same folder the Probe MCP server uses."""
    return Path.home() / '.trustabl-probe' / f'v{version}'


def _fetch(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url, timeout=120) as response, dest.open('wb') as out:
        shutil.copyfileobj(response, out)


def _expected_sha256(version: str, asset: str) -> str:
    """Read this asset's digest out of the release's `checksums.txt`."""
    with urllib.request.urlopen(f'{RELEASE_URL}/v{version}/checksums.txt', timeout=60) as response:
        text = response.read().decode('utf-8')
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip('*') == asset:
            return parts[0]
    raise RuntimeError(f'{asset} is not listed in checksums.txt for v{version}')


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_binary(version: str) -> Path:
    """Return a path to the pinned Probe, downloading and verifying it if needed.

    Nothing is executed before the archive's SHA-256 matches the digest published
    in the release's `checksums.txt`. A mismatch deletes the download and raises.
    """
    asset, binary_name = platform_asset(version)
    target = cache_dir(version) / binary_name
    if target.exists():
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset
        _fetch(f'{RELEASE_URL}/v{version}/{asset}', archive)

        expected = _expected_sha256(version, asset)
        actual = _sha256(archive)
        if actual != expected:
            archive.unlink(missing_ok=True)
            raise RuntimeError(
                f'Checksum mismatch for {asset}: expected {expected}, got {actual}. '
                'The download was discarded and nothing was executed.'
            )

        if asset.endswith('.zip'):
            with zipfile.ZipFile(archive) as zf:
                zf.extract(binary_name, target.parent)
        else:
            with tarfile.open(archive) as tf:
                member = tf.getmember(binary_name)
                tf.extract(member, target.parent)

    target.chmod(target.stat().st_mode | 0o755)
    return target
