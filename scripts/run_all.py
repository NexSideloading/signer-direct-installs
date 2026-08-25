#!/usr/bin/env python3
"""
Main script to run the entire signing workflow.
This orchestrates downloading IPAs, fetching certificates, and signing apps.
Only re-signs when IPAs change or certificates are added/removed.
"""
import sys
import subprocess
from pathlib import Path

def run_script(script_name: str, *args) -> tuple[bool, any]:
    """Run a Python script and return success status and return value."""
    script_path = Path(__file__).parent / script_name
    
    if not script_path.exists():
        print(f"Error: Script not found: {script_path}")
        return False, None
    
    print(f"\n{'='*60}")
    print(f"Running: {script_name}")
    print('='*60)
    
    # Import and run the script directly to get return values
    import importlib.util
    spec = importlib.util.spec_from_file_location(script_name.replace('.py', ''), script_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules[script_name.replace('.py', '')] = module
        try:
            result = spec.loader.exec_module(module)
            # Call main() if it exists and has parameters
            if hasattr(module, 'main') and args:
                return_value = module.main(*args)
                return True, return_value
            elif hasattr(module, 'main'):
                return_value = module.main()
                return True, return_value
            return True, None
        except Exception as e:
            print(f"Error running {script_name}: {e}")
            return False, None
    else:
        # Fallback to subprocess if import fails
        result = subprocess.run([sys.executable, str(script_path)], cwd=Path(__file__).parent.parent)
        if result.returncode != 0:
            print(f"Error: {script_name} failed with exit code {result.returncode}")
            return False, None
        return True, None

def is_first_run(signed_apps_dir: Path) -> bool:
    """Check if this is the first run (signed_apps doesn't exist or is empty)."""
    if not signed_apps_dir.exists():
        return True
    
    # Check if directory is empty
    if not any(signed_apps_dir.iterdir()):
        return True
    
    return False

def main():
    """Main function to run all scripts with conditional logic."""
    repo_root = Path(__file__).parent.parent
    signed_apps_dir = repo_root / "signed_apps"
    
    print("Starting automated app signing workflow...")
    
    # Check if first run
    first_run = is_first_run(signed_apps_dir)
    if first_run:
        print("🚀 First run detected - will download IPAs, fetch certificates, and sign all apps")
    else:
        print("🔄 Incremental run - will check for changes and re-sign as needed")
    
    # Always run download_ipas to check for updates
    success, changed_ipas = run_script("download_ipas.py")
    if not success:
        print("❌ Failed to download/check IPAs")
        return 1
    
    # Always run fetch_certificates to check for changes
    success, (added_certs, removed_certs) = run_script("fetch_certificates.py")
    if not success:
        print("❌ Failed to fetch/check certificates")
        return 1
    
    # Determine if signing is needed
    needs_signing = False
    force_apps = []
    force_certs = []
    force_all = False
    
    if first_run:
        # First run - sign everything
        force_all = True
        needs_signing = True
        print("📝 First run: will sign all apps with all certificates")
    elif changed_ipas:
        # IPAs changed - re-sign those IPAs with all certificates
        force_apps = changed_ipas
        needs_signing = True
        print(f"📝 IPAs changed: {changed_ipas} - will re-sign with all certificates")
    elif added_certs:
        # New certificates added - re-sign all IPAs with new certificates
        force_certs = added_certs
        needs_signing = True
        print(f"📝 Certificates added: {added_certs} - will re-sign all apps with these certificates")
    elif removed_certs:
        # Certificates removed - cleanup handled by sign_apps.py
        needs_signing = True
        print(f"📝 Certificates removed: {removed_certs} - will cleanup signed apps")
        # Force signing with all certificates to ensure consistency after cleanup
        force_all = True
    else:
        # No changes
        print("✅ No changes detected - skipping signing")
    
    # Run sign_apps if needed
    if needs_signing:
        success, _ = run_script("sign_apps.py", force_apps, force_certs, force_all)
        if not success:
            print("❌ Failed to sign apps")
            return 1
    
    print("\n" + "="*60)
    print("Workflow Summary")
    print("="*60)
    
    if first_run:
        print("✅ First run completed successfully!")
    elif changed_ipas:
        print(f"✅ Updated {len(changed_ipas)} changed IPA(s)")
    elif added_certs:
        print(f"✅ Added {len(added_certs)} new certificate(s)")
    elif removed_certs:
        print(f"✅ Removed {len(removed_certs)} certificate(s)")
    else:
        print("✅ No changes needed - everything is up to date")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())