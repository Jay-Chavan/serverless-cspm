#!/usr/bin/env python3
"""
KMS Lambda Deployment Script
Creates a deployment package for the KMS Lambda function
"""

import os
import zipfile
import shutil
import subprocess
import sys
from pathlib import Path

def create_kms_lambda_package():
    """Create deployment package for KMS Lambda function"""
    
    # Define paths
    script_dir = Path(__file__).parent
    kms_lambda_dir = script_dir / "kms_lambda"
    package_dir = script_dir / "kms_lambda_package"
    zip_file = script_dir / "kms_lambda.zip"
    
    print("=" * 60)
    print("KMS LAMBDA DEPLOYMENT PACKAGE CREATION")
    print("=" * 60)
    
    # Clean up previous builds
    if package_dir.exists():
        print(f"[INFO] Cleaning up previous build: {package_dir}")
        shutil.rmtree(package_dir)
    
    if zip_file.exists():
        print(f"[INFO] Removing previous zip file: {zip_file}")
        zip_file.unlink()
    
    # Create package directory
    package_dir.mkdir(exist_ok=True)
    print(f"[INFO] Created package directory: {package_dir}")
    
    # Copy source files
    print("[INFO] Copying source files...")
    source_files = [
        "lambda_handler.py",
        "KMSAudit.py", 
        "kms_opa_client.py"
    ]
    
    for file_name in source_files:
        src_file = kms_lambda_dir / file_name
        if src_file.exists():
            dst_file = package_dir / file_name
            shutil.copy2(src_file, dst_file)
            print(f"[INFO] Copied: {file_name}")
        else:
            print(f"[WARNING] Source file not found: {src_file}")
    
    # Copy helper functions if they exist
    helper_dir = kms_lambda_dir / "helper_functions"
    if helper_dir.exists():
        dst_helper_dir = package_dir / "helper_functions"
        shutil.copytree(helper_dir, dst_helper_dir)
        print(f"[INFO] Copied helper_functions directory")
    
    # Install dependencies
    print("[INFO] Installing dependencies...")
    requirements_file = kms_lambda_dir / "requirements.txt"
    if requirements_file.exists():
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "-r", str(requirements_file),
                "-t", str(package_dir),
                "--no-deps"
            ], check=True, capture_output=True, text=True)
            print("[INFO] Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install dependencies: {e}")
            print(f"[ERROR] stdout: {e.stdout}")
            print(f"[ERROR] stderr: {e.stderr}")
            return False
    else:
        print(f"[WARNING] Requirements file not found: {requirements_file}")
    
    # Create zip file
    print("[INFO] Creating deployment zip file...")
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(package_dir)
                zipf.write(file_path, arcname)
                print(f"[INFO] Added to zip: {arcname}")
    
    # Get zip file size
    zip_size = zip_file.stat().st_size / (1024 * 1024)  # MB
    print(f"[INFO] Deployment package created: {zip_file}")
    print(f"[INFO] Package size: {zip_size:.2f} MB")
    
    # Clean up package directory
    shutil.rmtree(package_dir)
    print(f"[INFO] Cleaned up temporary directory: {package_dir}")
    
    print("\n" + "=" * 60)
    print("KMS LAMBDA PACKAGE CREATION COMPLETED")
    print("=" * 60)
    print(f"Deployment package: {zip_file}")
    print(f"Ready for Terraform deployment!")
    
    return True

def main():
    """Main function"""
    try:
        success = create_kms_lambda_package()
        if success:
            print("\n[SUCCESS] KMS Lambda deployment package created successfully!")
            return 0
        else:
            print("\n[ERROR] Failed to create KMS Lambda deployment package!")
            return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())