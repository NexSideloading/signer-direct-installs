#!/usr/bin/env python3
import os
import sys
import requests
import json
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

# API endpoints
API_BASE = "https://sideloading.net/api/certificates"
LIST_ENDPOINTS = {
    "all": "/list/all",
    "signed": "/list/signed", 
    "revoked": "/list/revoked",
    "missingP12": "/list/missingP12"
}

# State file to track certificates
STATE_FILE = Path(__file__).parent.parent / "certificates_state.json"

# Certificate storage directory
CERT_DIR = Path(__file__).parent.parent / "certificates"

def load_state() -> Dict:
    """Load the current state of certificates."""
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(state: Dict):
    """Save the current state of certificates."""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def fetch_certificates(status: str = "all") -> List[Dict]:
    """Fetch certificates from the API."""
    endpoint = f"{API_BASE}{LIST_ENDPOINTS.get(status, LIST_ENDPOINTS['all'])}"
    
    try:
        response = requests.get(endpoint, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch certificates: {e}")
        return []

def download_certificate_file(cert_id: int, file_type: str, output_path: Path, is_missing_p12: bool = False) -> bool:
    """Download a certificate file from the API."""
    if is_missing_p12:
        endpoint = f"{API_BASE}/download/missingP12/{cert_id}/{file_type}"
    else:
        endpoint = f"{API_BASE}/download/{cert_id}/{file_type}"
    
    try:
        response = requests.get(endpoint, timeout=30)
        response.raise_for_status()
        
        # Save the file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(response.content)
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"  Failed to download {file_type} for cert {cert_id}: {e}")
        return False

def download_certificate_zip(cert_id: int, cert_name: str, output_dir: Path, is_missing_p12: bool = False) -> bool:
    """Download and extract certificate zip file."""
    if is_missing_p12:
        endpoint = f"{API_BASE}/download/missingP12/{cert_id}/cert.zip"
    else:
        endpoint = f"{API_BASE}/download/{cert_id}/cert.zip"
    
    zip_path = output_dir / f"{cert_name}.zip"
    
    try:
        response = requests.get(endpoint, timeout=30)
        response.raise_for_status()
        
        # Save zip file
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        # Extract zip file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        
        # Remove zip file
        zip_path.unlink()
        
        return True
    except requests.exceptions.RequestException as e:
        print(f"  Failed to download cert.zip for {cert_name}: {e}")
        if zip_path.exists():
            zip_path.unlink()
        return False
    except zipfile.BadZipFile as e:
        print(f"  Failed to extract cert.zip for {cert_name}: {e}")
        if zip_path.exists():
            zip_path.unlink()
        return False

def get_certificate_files(cert_dir: Path) -> Dict[str, Optional[Path]]:
    """Get paths to certificate files if they exist."""
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

def main():
    """Main function to fetch and download certificates."""
    # Create certificates directory
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load current state
    state = load_state()
    
    print("Fetching certificates from NexCerts API...")
    print("=" * 50)
    
    # Fetch all certificates
    all_certs = fetch_certificates("all")
    
    if not all_certs:
        print("No certificates found or failed to fetch")
        return [], []
    
    print(f"Found {len(all_certs)} certificates")
    
    # Process each certificate
    current_cert_ids = set()
    added_certs = []
    
    for cert in all_certs:
        cert_id = cert['id']
        cert_name = cert['name']
        cert_status = cert['status']
        folder_name = cert.get('folder_name', f"cert_{cert_id}")
        
        current_cert_ids.add(cert_id)
        
        # Check if this is a new certificate
        if str(cert_id) not in state:
            added_certs.append(str(cert_id))
            print(f"  ➕ New certificate: {cert_name} (ID: {cert_id})")
        
        # Create certificate directory
        cert_dir = CERT_DIR / folder_name
        cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Check if this is a missing P12 certificate
        is_missing_p12 = "missingp12" in cert_status.lower() or "missing p12" in cert_status.lower()
        
        print(f"Processing certificate: {cert_name} (ID: {cert_id}, Status: {cert_status})")
        
        # Download certificate files
        if is_missing_p12:
            # For missing P12, only download mobileprovision
            print(f"  Downloading mobileprovision only (missing P12)")
            success = download_certificate_file(
                cert_id, 
                "cert.mobileprovision", 
                cert_dir / "cert.mobileprovision",
                is_missing_p12=True
            )
        else:
            # Download full certificate bundle
            print(f"  Downloading certificate bundle")
            success = download_certificate_zip(cert_id, folder_name, cert_dir, is_missing_p12=False)
        
        if success:
            # Verify files were downloaded
            cert_files = get_certificate_files(cert_dir)
            
            if is_missing_p12:
                if cert_files['mobileprovision']:
                    print(f"  ✅ Certificate files downloaded successfully")
                else:
                    print(f"  ❌ Failed to download mobileprovision file")
            else:
                if cert_files['p12'] and cert_files['mobileprovision'] and cert_files['password']:
                    print(f"  ✅ Certificate files downloaded successfully")
                else:
                    print(f"  ⚠️  Some certificate files may be missing")
            
            # Update state
            state[str(cert_id)] = {
                'name': cert_name,
                'status': cert_status,
                'folder_name': folder_name,
                'is_missing_p12': is_missing_p12,
                'valid_from': cert.get('valid_from', ''),
                'valid_to': cert.get('valid_to', '')
            }
        else:
            print(f"  ❌ Failed to download certificate files")
    
    # Remove certificates that are no longer in the API
    removed_certs = []
    for cert_id_str in list(state.keys()):
        if int(cert_id_str) not in current_cert_ids:
            removed_certs.append(cert_id_str)
            cert_info = state[cert_id_str]
            folder_name = cert_info.get('folder_name', f"cert_{cert_id_str}")
            cert_dir = CERT_DIR / folder_name
            
            # Remove certificate directory
            if cert_dir.exists():
                import shutil
                shutil.rmtree(cert_dir)
                print(f"🗑️  Removed certificate: {cert_info['name']} (ID: {cert_id_str})")
            
            del state[cert_id_str]
    
    # Clean up orphaned certificate directories (exist on disk but not in state)
    tracked_folder_names = {cert_info.get('folder_name', f"cert_{cert_id}") for cert_id, cert_info in state.items()}
    orphaned_count = 0
    orphaned_folder_names = []
    for cert_dir in CERT_DIR.iterdir():
        if cert_dir.is_dir() and cert_dir.name not in tracked_folder_names:
            import shutil
            print(f"🗑️  Removing orphaned certificate directory: {cert_dir.name}")
            shutil.rmtree(cert_dir)
            orphaned_count += 1
            orphaned_folder_names.append(cert_dir.name)
    
    # Clean up signed apps for orphaned certificates
    if orphaned_folder_names:
        import shutil
        signed_apps_dir = Path(__file__).parent.parent / "signed_apps"
        if signed_apps_dir.exists():
            for app_dir in signed_apps_dir.iterdir():
                if app_dir.is_dir():
                    for cert_dir in app_dir.iterdir():
                        if cert_dir.is_dir() and cert_dir.name in orphaned_folder_names:
                            print(f"🗑️  Removing signed app for orphaned certificate: {app_dir.name}/{cert_dir.name}")
                            shutil.rmtree(cert_dir)
    
    if removed_certs:
        print(f"Removed {len(removed_certs)} certificates that are no longer available")
    
    if orphaned_count > 0:
        print(f"Cleaned up {orphaned_count} orphaned certificate directories")
        # Signal that certificates were removed to trigger cleanup in sign_apps
        removed_certs.append("orphaned_directories")
    
    # Save updated state
    save_state(state)
    
    print("=" * 50)
    print(f"Certificate sync completed. Active certificates: {len(state)}")
    print(f"Added certificates: {len(added_certs)}, Removed certificates: {len(removed_certs)}")
    
    # Check if we have certificates that need signing (certificates exist but aren't in signed_apps)
    # This handles the case where certificates were downloaded but signing was skipped
    signed_apps_dir = Path(__file__).parent.parent / "signed_apps"
    certs_needing_signing = []
    
    if signed_apps_dir.exists():
        for cert_id, cert_info in state.items():
            folder_name = cert_info.get('folder_name', f"cert_{cert_id}")
            cert_dir = CERT_DIR / folder_name
            
            # Check if certificate files exist
            cert_files = get_certificate_files(cert_dir)
            has_files = cert_files['p12'] and cert_files['mobileprovision'] and cert_files['password']
            
            if has_files:
                # Check if this certificate has been used to sign any app
                has_signed_apps = False
                for app_dir in signed_apps_dir.iterdir():
                    if app_dir.is_dir():
                        app_cert_dir = app_dir / folder_name
                        if app_cert_dir.exists():
                            has_signed_apps = True
                            break
                
                if not has_signed_apps:
                    certs_needing_signing.append(str(cert_id))
    
    if certs_needing_signing:
        print(f"Certificates needing signing: {len(certs_needing_signing)} ({certs_needing_signing})")
        # Treat these as added certificates to trigger signing
        added_certs.extend(certs_needing_signing)
    
    # Return added and removed certificate IDs for use by other scripts
    return added_certs, removed_certs

if __name__ == "__main__":
    main()