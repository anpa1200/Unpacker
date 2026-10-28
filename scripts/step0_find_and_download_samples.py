#!/usr/bin/env python3
"""
Find and download malware samples from Malware Bazaar for each packer type.

- Queries by tag or YARA rule (get_taginfo / get_yarainfo)
- Downloads each sample (get_file) — returns ZIP with password "infected"
- Extracts from ZIP (using pyzipper for AES)
- Renames to: {original_stem}_{packer_type}.{ext}

Requires: MALWARE_BAZAAR_API_KEY or MALWAREBAZAAR_AUTH_KEY in environment.
Get a free key: https://auth.abuse.ch/
"""
from __future__ import annotations

import argparse
import io
import os
import re
import sys
import time
import zipfile
import hashlib
import tempfile
import json
from pathlib import Path

try:
    import pyzipper
except ImportError:
    pyzipper = None

import requests

# Packer types we support; for each: (packer_id, tag to try, optional YARA rule fallback)
# Malware Bazaar uses tags (user-defined) and YARA rules (e.g. upx_packed). Try tag first.
PACKER_SOURCES = [
    ("upx", "UPX", "upx_packed"),
    ("aspack", "ASPack", None),
    ("mpress", "MPRESS", "mpress"),
    ("vmprotect", "VMProtect", None),
    ("themida", "Themida", None),
    ("enigma", "Enigma", None),
    ("nspack", "NSPack", None),
]

API_BASE = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
# Rate limit: avoid hammering the API
DELAY_BETWEEN_DOWNLOADS = 1.0
DELAY_AFTER_QUERY = 0.5


def get_auth_key() -> str:
    key = os.environ.get("MALWARE_BAZAAR_API_KEY") or os.environ.get("MALWAREBAZAAR_AUTH_KEY")
    if not key:
        raise SystemExit(
            "Error: Set MALWARE_BAZAAR_API_KEY or MALWAREBAZAAR_AUTH_KEY (get one at https://auth.abuse.ch/)"
        )
    return key.strip()


def sanitize_filename(name: str) -> str:
    """Remove or replace characters unsafe for filenames."""
    name = re.sub(r'[<>:"/\\|?*]', "_", name)
    name = name.strip(". ") or "unnamed"
    return name[:200]


def query_by_tag(auth_key: str, tag: str, limit: int) -> list[dict]:
    """Return list of sample entries (sha256_hash, file_name, ...) for the tag."""
    r = requests.post(
        API_BASE,
        data={"query": "get_taginfo", "tag": tag, "limit": limit},
        headers={"Auth-Key": auth_key},
        timeout=60,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") == "tag_not_found":
        return []
    if data.get("query_status") == "no_results":
        return []
    if data.get("query_status") != "ok":
        return []
    return data.get("data") or []


def query_by_yara(auth_key: str, yara_rule: str, limit: int) -> list[dict]:
    """Return list of sample entries for the YARA rule."""
    r = requests.post(
        API_BASE,
        data={"query": "get_yarainfo", "yara_rule": yara_rule, "limit": limit},
        headers={"Auth-Key": auth_key},
        timeout=60,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") == "yara_not_found":
        return []
    if data.get("query_status") == "no_results":
        return []
    if data.get("query_status") != "ok":
        return []
    return data.get("data") or []


def fetch_hashes_for_packer(
    auth_key: str,
    packer_id: str,
    tag: str,
    yara_fallback: str | None,
    limit: int,
) -> list[dict]:
    """Get sample list: try tag first, then YARA if configured."""
    out = query_by_tag(auth_key, tag, limit)
    if out:
        return out
    if yara_fallback:
        time.sleep(DELAY_AFTER_QUERY)
        out = query_by_yara(auth_key, yara_fallback, limit)
    return out


def download_sample(auth_key: str, sha256: str) -> bytes:
    """Download sample as ZIP bytes."""
    if not re.fullmatch(r"[a-fA-F0-9]{64}",sha256):
        raise ValueError("Invalid requested SHA-256")
    r = requests.post(
        API_BASE,
        data={"query": "get_file", "sha256_hash": sha256},
        headers={"Auth-Key": auth_key},
        timeout=120,
        stream=True,
    )
    r.raise_for_status()
    chunks=[]
    size=0
    try:
        for chunk in r.iter_content(65536):
            size+=len(chunk)
            if size>8*1024*1024:raise RuntimeError("Download exceeds size limit")
            chunks.append(chunk)
    finally:
        r.close()
    content=b"".join(chunks)
    if not content:
        raise RuntimeError("API returned empty response")
    # ZIP files start with PK
    if content[:2] == b"PK":
        return content
    # Otherwise API may have returned JSON error (e.g. file_not_found, rate limit)
    try:
        j = json.loads(content)
        status = j.get("query_status", "unknown")
        raise RuntimeError(f"API error: {status}")
    except ValueError:
        raise RuntimeError("API did not return a ZIP file (no PK header) and response is not JSON")


def extract_zip(zip_bytes: bytes, dest_dir: Path, password: bytes = ZIP_PASSWORD) -> Path | None:
    """Extract one bounded member into a new quarantine directory, never by archive path."""
    if len(zip_bytes)>8*1024*1024:
        raise ValueError("Archive download too large")
    archive_type=pyzipper.AESZipFile if pyzipper else zipfile.ZipFile
    with archive_type(io.BytesIO(zip_bytes),"r") as zf:
        members=[m for m in zf.infolist() if not m.is_dir()]
        if len(members)!=1:raise ValueError("Expected exactly one sample member")
        member=members[0]
        normalized=member.filename.replace("\\\\","/")
        if normalized.startswith("/") or ".." in normalized.split("/") or ":" in normalized:
            raise ValueError("Unsafe archive member path")
        if not 0<member.file_size<=32*1024*1024 or member.file_size>max(1,member.compress_size)*1000:
            raise ValueError("Archive expansion exceeds limits")
        dest_dir.mkdir(parents=True,exist_ok=True)
        quarantine=Path(tempfile.mkdtemp(prefix="quarantine-",dir=dest_dir))
        target=quarantine/"sample.bin"
        try:
            with zf.open(member,pwd=password) as source, target.open("xb") as output:
                total=0
                while True:
                    data=source.read(65536)
                    if not data:break
                    total+=len(data)
                    if total>32*1024*1024:raise ValueError("Expanded sample too large")
                    output.write(data)
            target.chmod(0o600)
            return target
        except BaseException:
            target.unlink(missing_ok=True)
            quarantine.rmdir()
            raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download Malware Bazaar samples per packer type; extract and rename."
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("samples_by_packer"),
        help="Base directory for per-packer subdirs",
    )
    parser.add_argument(
        "--per-packer",
        type=int,
        default=5,
        help="Max samples to download per packer type (default 5)",
    )
    parser.add_argument(
        "--limit-query",
        type=int,
        default=100,
        help="Max results to request from API per query (default 100)",
    )
    parser.add_argument(
        "--packer",
        action="append",
        dest="packers",
        help="Restrict to these packer ids (e.g. --packer upx --packer aspack)",
    )
    parser.add_argument("--extract", action="store_false", dest="no_extract", help="Explicitly extract into bounded quarantine")
    parser.add_argument(
        "--no-extract",
        action="store_true",
        default=True,
        help="Keep encrypted ZIPs only (default)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only list what would be downloaded",
    )
    args = parser.parse_args()

    auth_key = get_auth_key()

    if not pyzipper and not args.no_extract:
        print(
            "Warning: pyzipper not installed; ZIPs may use AES. Install with: pip install pyzipper",
            file=sys.stderr,
        )

    packers_to_run = [
        (pid, tag, yara)
        for pid, tag, yara in PACKER_SOURCES
        if not args.packers or pid in [p.lower() for p in args.packers]
    ]

    for packer_id, tag, yara_fallback in packers_to_run:
        print(f"\n--- Packer: {packer_id} (tag={tag}, yara_fallback={yara_fallback}) ---")
        entries = fetch_hashes_for_packer(
            auth_key, packer_id, tag, yara_fallback, limit=args.limit_query
        )
        if not entries:
            print(f"  No samples found for {packer_id}")
            continue
        print(f"  Found {len(entries)} samples, downloading up to {args.per_packer}")
        packer_dir = args.output_dir / packer_id
        packer_dir.mkdir(parents=True, exist_ok=True)
        downloaded = 0
        for i, entry in enumerate(entries):
            if downloaded >= args.per_packer:
                break
            sha256 = entry.get("sha256_hash")
            file_name = entry.get("file_name") or f"{sha256}.bin"
            if not sha256 or not re.fullmatch(r"[a-fA-F0-9]{64}",str(sha256)):
                continue
            stem = Path(file_name).stem
            stem = sanitize_filename(stem)
            ext = ".bin"
            final_name = f"{stem}_{packer_id}{ext}"
            out_path = packer_dir / final_name
            zip_path = packer_dir / f"{sha256}.zip"
            if out_path.exists() or zip_path.exists():
                print(f"  Skip (exists): {final_name}")
                downloaded += 1
                continue
            if args.dry_run:
                print(f"  Would download: {sha256} -> {final_name}")
                downloaded += 1
                continue
            try:
                zip_bytes = download_sample(auth_key, sha256)
                time.sleep(DELAY_BETWEEN_DOWNLOADS)
            except Exception as e:
                print(f"  Download failed {sha256}: {e}", file=sys.stderr)
                continue
            if args.no_extract:
                zip_path.write_bytes(zip_bytes)
                print(f"  Saved ZIP: {zip_path.name}")
            else:
                try:
                    extracted = extract_zip(zip_bytes, packer_dir)
                    if extracted and extracted.exists():
                        if hashlib.sha256(extracted.read_bytes()).hexdigest().lower() != sha256.lower():
                            extracted.unlink()
                            raise ValueError("Extracted sample SHA-256 does not match requested identity")
                        target = packer_dir / final_name
                        if target != extracted:
                            extracted.rename(target)
                        print(f"  Extracted -> {target.name}")
                    else:
                        zip_path.write_bytes(zip_bytes)
                        print(f"  Extract failed, saved ZIP: {zip_path.name}")
                except Exception as e:
                    zip_path.write_bytes(zip_bytes)
                    print(f"  Extract error: {e}; saved ZIP: {zip_path.name}", file=sys.stderr)
            downloaded += 1
        print(f"  Done: {downloaded} samples for {packer_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
