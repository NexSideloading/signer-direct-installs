
#!/usr/bin/env python3

import hashlib
import json
import os
import plistlib
import zipfile

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests


# ============================================================
# IPA SOURCES
# ============================================================

IPA_SOURCES = {
    "Ksign": "https://github.com/Nyasami/Ksign/releases/latest/download/Ksign.ipa",
    "Feather": "https://github.com/claration/Feather/releases/latest/download/Feather.ipa",
    "ESign": "https://github.com/Neoncat-OG/TrollStore-IPAs/releases/download/ESign/ESign-5.0.2.ipa",
    "Scarlet": "https://github.com/NexSideloading/scarlet-ipa/raw/refs/heads/main/ScarletAlpha.ipa",
}


# ============================================================
# CONFIGURATION
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

IPA_DIR = REPO_ROOT / "ipas"
STATE_FILE = REPO_ROOT / "ipa_state.json"

USER_AGENT = "NexSideloading-Signer/1.0"

HEAD_TIMEOUT = 30
DOWNLOAD_TIMEOUT = (15, 180)
CHUNK_SIZE = 1024 * 1024


# ============================================================
# STATE MANAGEMENT
# ============================================================

def load_state() -> Dict[str, Any]:
    """Load the current state of downloaded IPAs."""

    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            state = json.load(file)

        if isinstance(state, dict):
            return state

        print("Warning: Invalid state format. Rebuilding state.")
        return {}

    except (OSError, json.JSONDecodeError) as exc:
        print(f"Warning: Could not load state: {exc}")
        return {}


def save_state(state: Dict[str, Any]) -> None:
    """Save state atomically to prevent corruption."""

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    temp_file = STATE_FILE.with_suffix(".json.tmp")

    try:
        with temp_file.open("w", encoding="utf-8") as file:
            json.dump(state, file, indent=2)
            file.write("\n")

        os.replace(temp_file, STATE_FILE)

    finally:
        temp_file.unlink(missing_ok=True)


# ============================================================
# HASHING
# ============================================================

def get_file_hash(filepath: Path) -> str:
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with filepath.open("rb") as file:
        for chunk in iter(
            lambda: file.read(CHUNK_SIZE),
            b"",
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# REMOTE CHECKING
# ============================================================

def get_remote_metadata(
    name: str,
    url: str,
) -> Tuple[Optional[Dict[str, Optional[str]]], bool]:
    """
    Check the remote file using HTTP HEAD.

    Returns:
        (metadata, not_found)

    Metadata includes:
        etag
        last_modified
        content_length
    """

    headers = {
        "User-Agent": USER_AGENT,
    }

    try:
        response = requests.head(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=HEAD_TIMEOUT,
        )

        if response.status_code == 404:
            print(f"  {name}: Remote file returned 404.")
            return None, True

        if response.status_code in (405, 501):
            print(f"  {name}: HEAD not supported. Will download and compare.")
            return None, False

        response.raise_for_status()

        metadata = {
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
            "content_length": response.headers.get("Content-Length"),
        }

        return metadata, False

    except requests.exceptions.RequestException as exc:
        print(f"  {name}: Remote metadata check failed: {exc}")
        print(f"  {name}: Falling back to downloading and comparing.")

        return None, False


def remote_matches_saved_state(
    remote: Optional[Dict[str, Optional[str]]],
    saved: Dict[str, Any],
    local_path: Path,
) -> bool:
    """
    Determine whether the remote IPA is unchanged.

    Requires:
        - Existing local file
        - Matching local SHA-256
        - Matching remote HTTP validator
    """

    if not remote or not local_path.is_file():
        return False

    saved_hash = saved.get("hash")

    if not saved_hash:
        return False

    try:
        local_hash = get_file_hash(local_path)

    except OSError:
        return False

    # Verify the local file has not changed.
    if local_hash != saved_hash:
        return False

    # Check remote file size when available.
    remote_size = remote.get("content_length")

    if remote_size:
        try:
            if local_path.stat().st_size != int(remote_size):
                return False

        except (ValueError, OSError):
            return False

    # ETag is the preferred validator.
    remote_etag = remote.get("etag")
    saved_etag = saved.get("etag")

    if remote_etag:
        if saved_etag:
            return remote_etag == saved_etag

        # We have no saved ETag, so perform a download
        # to establish the initial remote state.
        return False

    # Fall back to Last-Modified + Content-Length.
    remote_modified = remote.get("last_modified")
    saved_modified = saved.get("last_modified")
    saved_size = saved.get("content_length")

    if (
        remote_modified
        and saved_modified
        and remote_size
        and saved_size
    ):
        return (
            remote_modified == saved_modified
            and str(remote_size) == str(saved_size)
        )

    # No reliable remote validator.
    # Download and compare actual file hashes.
    return False


# ============================================================
# IPA VALIDATION
# ============================================================

def validate_ipa(filepath: Path) -> bool:
    """
    Validate that the downloaded file is a real IPA.

    Checks:
        - Valid ZIP archive
        - Payload directory
        - Application Info.plist
        - Readable property list
    """

    try:
        with zipfile.ZipFile(filepath, "r") as archive:

            names = archive.namelist()

            info_plist_path = next(
                (
                    name
                    for name in names
                    if name.startswith("Payload/")
                    and name.endswith(".app/Info.plist")
                ),
                None,
            )

            if not info_plist_path:
                print(
                    "  Invalid IPA: "
                    "Payload/*.app/Info.plist not found."
                )
                return False

            plist_data = archive.read(info_plist_path)

            plist = plistlib.loads(plist_data)

            if not isinstance(plist, dict):
                print("  Invalid IPA: Info.plist is not a dictionary.")
                return False

        if filepath.stat().st_size == 0:
            print("  Invalid IPA: File is empty.")
            return False

        return True

    except (
        OSError,
        zipfile.BadZipFile,
        KeyError,
        plistlib.InvalidFileException,
        ValueError,
    ) as exc:

        print(f"  IPA validation failed: {exc}")
        return False


# ============================================================
# DOWNLOAD
# ============================================================

def download_ipa(
    name: str,
    url: str,
    output_dir: Path,
) -> Tuple[Optional[Path], Dict[str, Optional[str]]]:
    """
    Download an IPA into a temporary file.

    The existing IPA is never deleted until the new download
    has been fully downloaded and validated.
    """

    temp_path = output_dir / f".{name}.ipa.tmp"

    headers = {
        "User-Agent": USER_AGENT,
    }

    temp_path.unlink(missing_ok=True)

    try:
        print(f"  Downloading {name}...")

        with requests.get(
            url,
            headers=headers,
            stream=True,
            allow_redirects=True,
            timeout=DOWNLOAD_TIMEOUT,
        ) as response:

            if response.status_code == 404:
                print(f"  {name}: Remote file returned 404.")
                return None, {}

            response.raise_for_status()

            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            # Reject HTML and other obvious error responses.
            invalid_types = (
                "text/",
                "application/json",
                "application/xml",
            )

            if content_type.startswith(invalid_types):
                print(
                    f"  {name}: Expected IPA but received "
                    f"{content_type}."
                )
                return None, {}

            metadata = {
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
                "content_length": response.headers.get("Content-Length"),
            }

            downloaded_bytes = 0

            with temp_path.open("wb") as file:

                for chunk in response.iter_content(
                    chunk_size=CHUNK_SIZE
                ):

                    if not chunk:
                        continue

                    file.write(chunk)
                    downloaded_bytes += len(chunk)

                    if downloaded_bytes % (50 * 1024 * 1024) < CHUNK_SIZE:
                        print(
                            f"  {name}: Downloaded "
                            f"{downloaded_bytes / (1024 * 1024):.1f} MB"
                        )

        if not temp_path.exists() or temp_path.stat().st_size == 0:
            print(f"  {name}: Downloaded file is empty.")
            return None, {}

        if not validate_ipa(temp_path):
            print(f"  {name}: Invalid IPA. Keeping existing version.")
            return None, {}

        print(
            f"  {name}: Downloaded successfully "
            f"({temp_path.stat().st_size:,} bytes)."
        )

        return temp_path, metadata

    except requests.exceptions.Timeout:
        print(f"  {name}: Download timed out.")

    except requests.exceptions.RequestException as exc:
        print(f"  {name}: Download failed: {exc}")

    except OSError as exc:
        print(f"  {name}: File operation failed: {exc}")

    except Exception as exc:
        print(f"  {name}: Unexpected error: {exc}")

    temp_path.unlink(missing_ok=True)

    return None, {}


# ============================================================
# MAIN
# ============================================================

def main() -> list[str]:
    """Download updated IPAs and return successfully changed apps."""

    IPA_DIR.mkdir(parents=True, exist_ok=True)

    state = load_state()

    changed_ipas = []

    print("Checking upstream IPA releases...")
    print("=" * 60)

    for name, url in IPA_SOURCES.items():

        print(f"\nChecking {name}...")

        output_path = IPA_DIR / f"{name}.ipa"

        previous_state = state.get(name, {})

        if not isinstance(previous_state, dict):
            previous_state = {}

        # ----------------------------------------------------
        # 1. Check upstream metadata.
        # ----------------------------------------------------

        remote_metadata, not_found = get_remote_metadata(
            name,
            url,
        )

        if not_found:
            print(f"  {name}: Keeping existing IPA.")
            continue

        # ----------------------------------------------------
        # 2. Check whether the remote asset is unchanged.
        # ----------------------------------------------------

        if remote_matches_saved_state(
            remote_metadata,
            previous_state,
            output_path,
        ):

            print(f"  {name}: Already up to date.")
            continue

        print(f"  {name}: Remote asset needs verification.")

        # Save existing hash before downloading.
        existing_hash = None

        if output_path.is_file():
            try:
                existing_hash = get_file_hash(output_path)

            except OSError as exc:
                print(f"  {name}: Could not hash existing file: {exc}")

        # ----------------------------------------------------
        # 3. Download the latest remote IPA.
        # ----------------------------------------------------

        temp_path, download_metadata = download_ipa(
            name,
            url,
            IPA_DIR,
        )

        if temp_path is None:
            print(f"  {name}: Keeping existing version after failure.")
            continue

        # ----------------------------------------------------
        # 4. Calculate the downloaded hash.
        # ----------------------------------------------------

        try:
            downloaded_hash = get_file_hash(temp_path)

            old_state_hash = previous_state.get("hash")

            # Compare the downloaded IPA against the existing one.
            file_changed = downloaded_hash != existing_hash

            # Also detect a previously interrupted update where
            # the IPA was replaced but its state wasn't saved.
            state_outdated = (
                old_state_hash is not None
                and downloaded_hash != old_state_hash
            )

            # ------------------------------------------------
            # 5. Replace the old IPA if necessary.
            # ------------------------------------------------

            if file_changed:

                os.replace(temp_path, output_path)

                print(
                    f"  {name}: Updated successfully "
                    f"({output_path.stat().st_size:,} bytes)."
                )

            else:

                temp_path.unlink(missing_ok=True)

                print(f"  {name}: Downloaded IPA is identical.")

            # ------------------------------------------------
            # 6. Update state.
            # ------------------------------------------------

            metadata = {
                **(remote_metadata or {}),
                **download_metadata,
            }

            state[name] = {
                "hash": downloaded_hash,
                "last_updated": str(output_path.stat().st_mtime),
                "etag": metadata.get("etag"),
                "last_modified": metadata.get("last_modified"),
                "content_length": (
                    metadata.get("content_length")
                    or str(output_path.stat().st_size)
                ),
            }

            # ------------------------------------------------
            # 7. Notify the signing workflow if changed.
            # ------------------------------------------------

            if file_changed or state_outdated:

                changed_ipas.append(name)

                if state_outdated and not file_changed:
                    print(
                        f"  {name}: State was outdated. "
                        "Marking for re-signing."
                    )

        except OSError as exc:

            print(f"  {name}: Failed to process downloaded IPA: {exc}")

            temp_path.unlink(missing_ok=True)

    # ========================================================
    # SAVE STATE
    # ========================================================

    save_state(state)

    print("\n" + "=" * 60)

    print(
        f"IPA check completed. "
        f"Changed IPAs: {len(changed_ipas)}"
    )

    if changed_ipas:
        print("Apps requiring re-signing:")

        for name in changed_ipas:
            print(f"  - {name}")

    else:
        print("All IPAs are up to date.")

    # IMPORTANT:
    # run_all.py uses this list to decide which apps need
    # re-signing.
    return changed_ipas


if __name__ == "__main__":
    main()
