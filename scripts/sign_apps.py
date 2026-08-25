#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import shutil
import zipfile
import tempfile
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
from urllib.parse import quote

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
IPA_DIR = REPO_ROOT / "ipas"
CERT_DIR = REPO_ROOT / "certificates"
OUTPUT_DIR = REPO_ROOT / "signed_apps"
STATE_FILE = REPO_ROOT / "signing_state.json"
CONFIG_FILE = REPO_ROOT / "config.json"

def load_config() -> Dict:
    """Load configuration from config.json."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

# Apps that require signing asset injection
APPS_REQUIRING_INJECTION = ["Ksign", "Feather"]

def load_state() -> Dict:
    """Load the current signing state."""
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(state: Dict):
    """Save the current signing state."""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def load_cert_state() -> Dict:
    """Load the certificate state."""
    cert_state_file = REPO_ROOT / "certificates_state.json"
    if cert_state_file.exists():
        with open(cert_state_file, 'r') as f:
            return json.load(f)
    return {}

def get_certificate_files(cert_dir: Path) -> Dict[str, Optional[Path]]:
    """Get paths to certificate files."""
    files = {
        'p12': None,
        'mobileprovision': None,
        'password': None
    }
    
    # Look for .p12 or .pfx file
    for ext in ['*.p12', '*.pfx']:
        matches = list(cert_dir.glob(ext))
        if matches:
            files['p12'] = matches[0]
            break
    
    # Look for .mobileprovision file
    mobileprovision_matches = list(cert_dir.glob('*.mobileprovision'))
    if mobileprovision_matches:
        files['mobileprovision'] = mobileprovision_matches[0]
    
    # Look for password file
    for pass_file in ['password.txt', 'password']:
        pass_path = cert_dir / pass_file
        if pass_path.exists():
            files['password'] = pass_path
            break
    
    return files

def get_password(password_file: Path) -> str:
    """Read password from file."""
    try:
        with open(password_file, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"  Failed to read password file: {e}")
        return ""

def is_certificate_expired(valid_to: str) -> bool:
    """Check if a certificate is expired based on valid_to date."""
    if not valid_to:
        return True  # Treat missing date as expired
    
    try:
        # Parse date format like "Jun 23 08:49:28 2027 GMT"
        cert_date = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y GMT")
        return datetime.utcnow() > cert_date
    except ValueError:
        print(f"  Failed to parse certificate expiry date: {valid_to}")
        return True  # Treat unparseable date as expired

def download_zsign(output_dir: Path) -> Optional[Path]:
    """Download zsign binary."""
    zsign_url = "https://github.com/zhlynn/zsign/releases/latest/download/zsign-linux-x86_64.tar.gz"
    zsign_path = output_dir / "zsign"
    
    if zsign_path.exists():
        try:
            # Test if zsign is executable
            result = subprocess.run([str(zsign_path), "--help"], capture_output=True, timeout=5)
            if result.returncode == 0:
                return zsign_path
        except Exception:
            pass
        
        # If test failed, remove and redownload
        zsign_path.unlink()
    
    print("  Downloading zsign...")
    
    try:
        response = requests.get(zsign_url, timeout=60)
        response.raise_for_status()
        
        tgz_path = output_dir / "zsign.tar.gz"
        with open(tgz_path, 'wb') as f:
            f.write(response.content)
        
        # Extract
        import tarfile
        try:
            with tarfile.open(tgz_path, 'r:gz') as tar:
                tar.extractall(output_dir)
        except tarfile.TarError as e:
            print(f"  Failed to extract zsign: {e}")
            tgz_path.unlink()
            return None
        
        # Make executable
        os.chmod(zsign_path, 0o755)
        
        # Cleanup
        tgz_path.unlink()
        
        return zsign_path
    except Exception as e:
        print(f"  Failed to download zsign: {e}")
        return None

def extract_metadata_from_signing_output(metadata_dir: Path, ipa_path: Path) -> Optional[Dict]:
    """Extract metadata from zsign signing output."""
    try:
        # Read metadata.json
        metadata_file = metadata_dir / "metadata.json"
        if not metadata_file.exists():
            print("  metadata.json not found after signing")
            return None
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        # Find the icon file (any .png file in the metadata folder)
        icon_files = list(metadata_dir.glob("*.png"))
        if icon_files:
            # Copy the icon to a permanent location
            icon_dir = REPO_ROOT / "icons"
            icon_dir.mkdir(parents=True, exist_ok=True)
            icon_name = f"{ipa_path.stem}_icon.png"
            icon_path = icon_dir / icon_name
            shutil.copy2(icon_files[0], icon_path)
            metadata['icon_path'] = str(icon_path)
        else:
            metadata['icon_path'] = None
        
        return metadata
    except Exception as e:
        print(f"  Failed to extract metadata from signing output: {e}")
        return None

def prepare_and_sign_ipa(ipa_path: Path, cert_files: Dict, output_path: Path, zsign_path: Path, app_name: str, cert_name: str) -> tuple[bool, Optional[Dict]]:
    """Prepare and sign an IPA using zsign, with optional asset injection before signing."""
    metadata = None
    
    if not cert_files['p12'] or not cert_files['mobileprovision'] or not cert_files['password']:
        print("  Missing certificate files for signing")
        return False, None
    
    password = get_password(cert_files['password'])
    if not password:
        print("  Failed to get password")
        return False, None
    
    # Create temporary directories for extraction and signing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        extracted_dir = temp_path / "extracted"
        metadata_dir = temp_path / "metadata"
        extracted_dir.mkdir()
        metadata_dir.mkdir()
        
        try:
            # Extract IPA
            print(f"  Extracting IPA...")
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extracted_dir)
            
            # Find .app directory
            payload_dir = extracted_dir / "Payload"
            app_dirs = list(payload_dir.glob("*.app"))
            
            if not app_dirs:
                print("  No .app directory found in IPA")
                return False, None
            
            app_dir = app_dirs[0]
            
            # Inject signing assets for specific apps BEFORE signing
            if app_name in APPS_REQUIRING_INJECTION:
                print(f"  Injecting signing assets before signing...")
                if not inject_signing_assets(app_dir, cert_files, cert_name):
                    print(f"  ⚠ Failed to inject signing assets")
            
            # Repackage IPA with injected assets
            modified_ipa = temp_path / "modified.ipa"
            print(f"  Repackaging IPA...")
            with zipfile.ZipFile(modified_ipa, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for root, dirs, files in os.walk(extracted_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(extracted_dir)
                        zip_ref.write(file_path, arcname)
            
            # Sign the modified IPA
            print(f"  Signing IPA with zsign...")
            cmd = [
                str(zsign_path),
                "-k", str(cert_files['p12']),
                "-m", str(cert_files['mobileprovision']),
                "-p", password,
                "-o", str(output_path),
                "-x", str(metadata_dir),
                str(modified_ipa)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                print(f"  zsign failed (exit code {result.returncode})")
                if result.stderr:
                    print(f"  stderr: {result.stderr[:500]}")
                if result.stdout:
                    print(f"  stdout: {result.stdout[:500]}")
                
                # Try with additional parameters that might help
                print("  Retrying with additional parameters...")
                cmd = [
                    str(zsign_path),
                    "-k", str(cert_files['p12']),
                    "-m", str(cert_files['mobileprovision']),
                    "-p", password,
                    "-o", str(output_path),
                    "-x", str(metadata_dir),
                    "--no-compress",
                    str(modified_ipa)
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode != 0:
                    print(f"  zsign retry also failed (exit code {result.returncode})")
                    return False, metadata
            
            # Verify the output file was created
            if not output_path.exists():
                print("  zsign completed but output file not created")
                return False, metadata
            
            # Verify the output file is valid
            if output_path.stat().st_size < 1000:  # Suspiciously small
                print("  Output file is too small, may be corrupted")
                output_path.unlink()
                return False, metadata
            
            # Extract metadata from signing output
            metadata = extract_metadata_from_signing_output(metadata_dir, ipa_path)
            if metadata:
                print(f"  Extracted metadata: {metadata.get('AppBundleIdentifier', 'unknown')} v{metadata.get('AppVersion', 'unknown')}")
            else:
                print("  Failed to extract metadata from signing output")
            
            return True, metadata
        except subprocess.TimeoutExpired:
            print("  zsign timed out")
            return False, metadata
        except Exception as e:
            print(f"  Signing error: {e}")
            return False, metadata

def inject_signing_assets(extracted_app_dir: Path, cert_files: Dict, cert_name: str) -> bool:
    """Inject signing assets into extracted app directory for apps that require it."""
    if not cert_files['p12'] or not cert_files['mobileprovision'] or not cert_files['password']:
        print("  Missing certificate files for injection")
        return False
    
    try:
        # Create signing-assets directory
        assets_dir = extracted_app_dir / "signing-assets" / cert_name
        assets_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy certificate files
        shutil.copy2(cert_files['p12'], assets_dir / "cert.p12")
        shutil.copy2(cert_files['mobileprovision'], assets_dir / "cert.mobileprovision")
        shutil.copy2(cert_files['password'], assets_dir / "cert.txt")
        
        return True
    except Exception as e:
        print(f"  Failed to inject signing assets: {e}")
        return False

def generate_manifest(ipa_url: str, app_name: str, version: str, bundle_id: str, title: str, output_path: Path, icon_path: Optional[str] = None) -> bool:
    """Generate install manifest plist."""
    config = load_config()
    # Use extracted icon if available, otherwise use generic placeholder
    if icon_path and Path(icon_path).exists():
        # Use icon URL template from config
        icon_filename = Path(icon_path).name
        icon_url_template = config.get('icon_url_template') or "https://raw.githubusercontent.com/{github_repo}/{github_ref}/icons/{icon_filename}"
        github_repo = config.get('github_repo') or os.environ.get('GITHUB_REPOSITORY', 'NexSideloading/signer-direct-installs')
        github_ref = config.get('github_ref') or os.environ.get('GITHUB_REF_NAME', 'main')
        icon_url = icon_url_template.format(
            github_repo=github_repo,
            github_ref=github_ref,
            icon_filename=icon_filename
        )
    else:
        icon_url = "https://sideloading.net/signer/fallback.png"
    
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{ipa_url}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>display-image</string>
                    <key>url</key>
                    <string>{icon_url}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>full-size-image</string>
                    <key>url</key>
                    <string>{icon_url}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{bundle_id}</string>
                <key>bundle-version</key>
                <string>{version}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>{title}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(plist_content)
        return True
    except Exception as e:
        print(f"  Failed to generate manifest: {e}")
        return False

def extract_ipa_version(ipa_path: Path) -> str:
    """Extract version from IPA."""
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            # Find Info.plist
            for name in zip_ref.namelist():
                if name.endswith(".app/Info.plist"):
                    plist_data = zip_ref.read(name)
                    
                    # Parse plist
                    import plistlib
                    plist_dict = plistlib.loads(plist_data)
                    
                    version = plist_dict.get("CFBundleShortVersionString") or plist_dict.get("CFBundleVersion") or "1.0"
                    return str(version)
    except Exception as e:
        print(f"  Failed to extract version: {e}")
    
    return "1.0"

def main(force_apps=None, force_certs=None, force_all=False):
    """Main function to sign apps with certificates.
    
    Args:
        force_apps: List of app names to force re-sign (e.g., ["Ksign", "Feather"])
        force_certs: List of certificate IDs to force re-sign with (e.g., ["123", "456"])
        force_all: Force re-sign all apps with all certificates
    """
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load states and config
    signing_state = load_state()
    cert_state = load_cert_state()
    config = load_config()
    
    if not cert_state:
        print("No certificates found. Run fetch_certificates.py first.")
        return
    
    print("Signing apps with certificates...")
    print("=" * 50)
    
    if force_all:
        print("Force re-signing all apps with all certificates")
    elif force_apps:
        print(f"Force re-signing apps: {force_apps}")
    elif force_certs:
        print(f"Force re-signing with certificates: {force_certs}")
    
    # Download zsign
    zsign_path = download_zsign(SCRIPT_DIR)
    if not zsign_path:
        print("Failed to download zsign")
        return
    
    # Process each IPA
    ipa_files = list(IPA_DIR.glob("*.ipa"))
    
    if not ipa_files:
        print("No IPA files found. Run download_ipas.py first.")
        return
    
    print(f"Found {len(ipa_files)} IPA files")
    print(f"Found {len(cert_state)} certificates")
    
    # Apply certificate filters from config
    cert_filters = config.get('cert_filters', {})
    include_revoked = cert_filters.get('include_revoked', False)
    include_missing_p12 = cert_filters.get('include_missing_p12', False)
    
    if not include_revoked or not include_missing_p12:
        print(f"Certificate filters: revoked={include_revoked}, missing_p12={include_missing_p12}")
    
    for ipa_path in ipa_files:
        app_name = ipa_path.stem
        print(f"\nProcessing app: {app_name}")
        
        # Extract IPA version
        ipa_version = extract_ipa_version(ipa_path)
        print(f"  Version: {ipa_version}")
        
        # Initialize app state if needed
        if app_name not in signing_state:
            signing_state[app_name] = {}
        
        # Process each certificate
        for cert_id_str, cert_info in cert_state.items():
            cert_id = int(cert_id_str)
            cert_name = cert_info['name']
            folder_name = cert_info['folder_name']
            is_missing_p12 = cert_info.get('is_missing_p12', False)
            is_revoked = "revoked" in cert_info['status'].lower() or "❌" in cert_info['status']
            valid_to = cert_info.get('valid_to', '')
            
            # Skip expired certificates
            if is_certificate_expired(valid_to):
                print(f"  Skipping {cert_name} (expired certificate, valid until: {valid_to})")
                continue
            
            # Skip missing P12 certificates for signing (they can't sign)
            if is_missing_p12:
                print(f"  Skipping {cert_name} (missing P12 file, cannot sign)")
                continue
            
            # Apply certificate filters for revoked certs
            if is_revoked and not include_revoked:
                print(f"  Skipping {cert_name} (revoked certificate)")
                continue
            
            cert_dir = CERT_DIR / folder_name
            cert_files = get_certificate_files(cert_dir)
            
            if not cert_files['p12'] or not cert_files['mobileprovision'] or not cert_files['password']:
                print(f"  Skipping {cert_name} (missing certificate files)")
                continue
            
            # Create output directory for this app/cert combination
            output_subdir = OUTPUT_DIR / app_name / cert_name
            
            signed_ipa_path = output_subdir / "signed.ipa"
            manifest_path = output_subdir / "manifest.plist"
            
            # Check if already signed with current IPA version
            state_key = f"{cert_id}"
            current_state = signing_state[app_name].get(state_key, {})
            
            # Determine if we need to re-sign
            needs_signing = False
            reason = ""
            
            if force_all:
                needs_signing = True
                reason = "force all"
            elif force_apps and app_name in force_apps:
                needs_signing = True
                reason = "force app"
            elif force_certs and cert_id_str in force_certs:
                needs_signing = True
                reason = "force certificate"
            elif not output_subdir.exists():
                # Certificate folder doesn't exist, need to sign
                needs_signing = True
                reason = "certificate folder missing"
            elif not current_state:
                # No signing state exists for this cert, need to sign
                needs_signing = True
                reason = "no signing state"
            elif not (current_state.get('ipa_hash') == ipa_version and current_state.get('cert_version') == cert_info.get('valid_to')):
                needs_signing = True
                reason = "version mismatch"
            elif not (signed_ipa_path.exists() and manifest_path.exists()):
                needs_signing = True
                reason = "signed files missing"
            
            # Create output directory if we need to sign
            if needs_signing:
                output_subdir.mkdir(parents=True, exist_ok=True)
                print(f"  Signing with {cert_name} ({reason})")
            
            if not needs_signing:
                print(f"  ✓ Already signed with {cert_name}")
                continue
            
            # Prepare and sign the IPA with optional asset injection
            sign_success, metadata = prepare_and_sign_ipa(ipa_path, cert_files, signed_ipa_path, zsign_path, app_name, cert_name)
            if not sign_success:
                print(f"  ✗ Failed to sign with {cert_name}")
                continue
            
            # Use extracted metadata or fallback to app_name
            bundle_id = metadata.get('AppBundleIdentifier', app_name) if metadata else app_name
            title = metadata.get('AppName', app_name) if metadata else app_name
            version = metadata.get('AppVersion', ipa_version) if metadata else ipa_version
            icon_path = metadata.get('icon_path') if metadata else None
            
            print(f"  Using metadata - Bundle ID: {bundle_id}, Title: {title}, Version: {version}")
            
            # Generate manifest
            # Use config or environment variables for GitHub hosting
            github_repo = config.get('github_repo') or os.environ.get('GITHUB_REPOSITORY', 'your-username/your-repo')
            github_ref = config.get('github_ref') or os.environ.get('GITHUB_REF_NAME', 'main')
            
            manifest_template = config.get('manifest_url_template') or "https://raw.githubusercontent.com/{github_repo}/{github_ref}/signed_apps/{app_name}/{cert_name}/signed.ipa"
            ipa_url = manifest_template.format(
                github_repo=github_repo,
                github_ref=github_ref,
                app_name=quote(app_name),
                cert_name=quote(cert_name)
            )
            
            if not generate_manifest(ipa_url, app_name, version, bundle_id, title, manifest_path, icon_path):
                print(f"  ✗ Failed to generate manifest")
                continue
            
            # Update state
            signing_state[app_name][state_key] = {
                'ipa_hash': ipa_version,
                'cert_version': cert_info.get('valid_to'),
                'cert_name': cert_name,
                'timestamp': str(Path(signed_ipa_path).stat().st_mtime)
            }
            
            print(f"  ✓ Successfully signed with {cert_name}")
    
    # Cleanup: Remove signed apps for certificates that no longer exist
    print("\nCleaning up obsolete signed apps...")
    
    # Get valid certificate folder names from state
    valid_cert_folder_names = {cert_info.get('folder_name', f"cert_{cert_id}") for cert_id, cert_info in cert_state.items()}
    
    for app_name in list(signing_state.keys()):
        for cert_id_str in list(signing_state[app_name].keys()):
            if cert_id_str not in cert_state:
                # Certificate no longer exists, remove signed files
                cert_name = signing_state[app_name][cert_id_str].get('cert_name', f"cert_{cert_id_str}")
                output_subdir = OUTPUT_DIR / app_name / cert_name
                
                shutil.rmtree(output_subdir, ignore_errors=True)
                print(f"  🗑️ Removed {app_name}/{cert_name}")
                
                del signing_state[app_name][cert_id_str]
        
        # Also clean up signed apps for orphaned certificates (exist on disk but not in state)
        app_dir = OUTPUT_DIR / app_name
        if app_dir.exists():
            for cert_dir in app_dir.iterdir():
                if cert_dir.is_dir() and cert_dir.name not in valid_cert_folder_names:
                    shutil.rmtree(cert_dir, ignore_errors=True)
                    print(f"  🗑️ Removed orphaned signed app: {app_name}/{cert_dir.name}")
        
        # Remove app entry if no certificates left
        if not signing_state[app_name]:
            del signing_state[app_name]
    
    # Save state
    save_state(signing_state)
    
    print("=" * 50)
    print("App signing completed")

if __name__ == "__main__":
    main()
