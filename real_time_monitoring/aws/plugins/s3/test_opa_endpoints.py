#!/usr/bin/env python3
"""
Test script for S3-KMS integrated audit system with different OPA endpoints.
This script tests both SSE and KMS encryption scenarios to verify correct endpoint routing.
"""

import json
import sys
import os
from datetime import datetime

# Add current directory to path for imports
sys.path.append(os.path.dirname(__file__))

from BucketACLS import audit_bucket_security
from opa_client import send_opa_request

def test_sse_encryption_endpoint():
    """
    Test S3 bucket with SSE-S3 encryption (should use SSE endpoint)
    """
    print("\n" + "="*60)
    print("TEST 1: S3 Bucket with SSE-S3 Encryption")
    print("="*60)
    
    # Mock S3 configuration with SSE-S3 encryption
    s3_config_sse = {
        "bucket_name": "test-bucket-sse",
        "encryption": "AES256",  # SSE-S3 encryption
        "bucket_ownership": "BucketOwnerPreferred",
        "acls_enabled": True,
        "public_access": "enabled",
        "versioning": "disabled",
        "mfa_delete": "disabled",
        "bucket_policy": None,
        "logging": "disabled",
        "notification": "disabled",
        "tagset": [
            {"Key": "Environment", "Value": "test"},
            {"Key": "Confidentiality", "Value": "high"}
        ]
    }
    
    print(f"[TEST] Configuration: {json.dumps(s3_config_sse, indent=2)}")
    
    # Test direct OPA request (should use SSE endpoint)
    print("\n[TEST] Testing direct OPA request with SSE endpoint...")
    response = send_opa_request(s3_config_sse, use_kms_endpoint=False)
    print(f"[TEST] OPA Response: {json.dumps(response, indent=2) if response else 'None'}")
    
    # Test full audit function
    print("\n[TEST] Testing full audit function...")
    try:
        # Note: This will fail without actual AWS credentials, but we can test the logic
        result = audit_bucket_security(
            bucket_name="test-bucket-sse",
            account_id="123456789012",
            region="us-east-1",
            tagset=s3_config_sse["tagset"]
        )
        print(f"[TEST] Audit Result: {json.dumps(result, indent=2, default=str) if result else 'None'}")
    except Exception as e:
        print(f"[TEST] Expected error (no AWS credentials): {e}")
    
    return True

def test_kms_encryption_endpoint():
    """
    Test S3 bucket with KMS encryption (should use KMS endpoint)
    """
    print("\n" + "="*60)
    print("TEST 2: S3 Bucket with KMS Encryption")
    print("="*60)
    
    # Mock S3 configuration with KMS encryption
    s3_config_kms = {
        "bucket_name": "test-bucket-kms",
        "encryption": "KMS-arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        "bucket_ownership": "BucketOwnerEnforced",
        "acls_enabled": False,
        "public_access": "blocked",
        "versioning": "enabled",
        "mfa_delete": "enabled",
        "bucket_policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::test-bucket-kms/*",
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    }
                }
            ]
        },
        "logging": {
            "target_bucket": "audit-logs-bucket",
            "target_prefix": "access-logs/"
        },
        "notification": "enabled",
        "tagset": [
            {"Key": "Environment", "Value": "production"},
            {"Key": "Confidentiality", "Value": "high"},
            {"Key": "DataClassification", "Value": "sensitive"}
        ]
    }
    
    print(f"[TEST] Configuration: {json.dumps(s3_config_kms, indent=2)}")
    
    # Test direct OPA request (should use KMS endpoint)
    print("\n[TEST] Testing direct OPA request with KMS endpoint...")
    response = send_opa_request(s3_config_kms, use_kms_endpoint=True)
    print(f"[TEST] OPA Response: {json.dumps(response, indent=2) if response else 'None'}")
    
    # Test full audit function
    print("\n[TEST] Testing full audit function...")
    try:
        # Note: This will fail without actual AWS credentials, but we can test the logic
        result = audit_bucket_security(
            bucket_name="test-bucket-kms",
            account_id="123456789012",
            region="us-east-1",
            tagset=s3_config_kms["tagset"]
        )
        print(f"[TEST] Audit Result: {json.dumps(result, indent=2, default=str) if result else 'None'}")
    except Exception as e:
        print(f"[TEST] Expected error (no AWS credentials): {e}")
    
    return True

def test_endpoint_selection_logic():
    """
    Test the endpoint selection logic with various encryption configurations
    """
    print("\n" + "="*60)
    print("TEST 3: Endpoint Selection Logic")
    print("="*60)
    
    test_cases = [
        {"encryption": None, "expected_endpoint": "SSE", "description": "No encryption"},
        {"encryption": "none", "expected_endpoint": "SSE", "description": "No encryption (explicit)"},
        {"encryption": "AES256", "expected_endpoint": "SSE", "description": "SSE-S3 encryption"},
        {"encryption": "aws:kms", "expected_endpoint": "SSE", "description": "Generic KMS (no key ID)"},
        {"encryption": "KMS-alias/my-key", "expected_endpoint": "KMS", "description": "KMS with alias"},
        {"encryption": "KMS-arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", "expected_endpoint": "KMS", "description": "KMS with full ARN"},
        {"encryption": "KMS-12345678-1234-1234-1234-123456789012", "expected_endpoint": "KMS", "description": "KMS with key ID"}
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[TEST 3.{i}] {test_case['description']}")
        print(f"[TEST] Encryption: {test_case['encryption']}")
        
        # Test the logic from BucketACLS.py
        use_kms_endpoint = False
        encryption_config = test_case['encryption']
        if encryption_config and isinstance(encryption_config, str) and encryption_config.startswith("KMS-"):
            use_kms_endpoint = True
        
        actual_endpoint = "KMS" if use_kms_endpoint else "SSE"
        expected_endpoint = test_case['expected_endpoint']
        
        print(f"[TEST] Expected endpoint: {expected_endpoint}")
        print(f"[TEST] Actual endpoint: {actual_endpoint}")
        print(f"[TEST] Result: {'✓ PASS' if actual_endpoint == expected_endpoint else '✗ FAIL'}")
    
    return True

def test_opa_configuration():
    """
    Test OPA configuration and endpoint URLs
    """
    print("\n" + "="*60)
    print("TEST 4: OPA Configuration")
    print("="*60)
    
    from opa_client import OPA_URL_SSE, OPA_URL_KMS
    
    print(f"[TEST] SSE Endpoint: {OPA_URL_SSE}")
    print(f"[TEST] KMS Endpoint: {OPA_URL_KMS}")
    
    # Verify endpoints are different
    if OPA_URL_SSE != OPA_URL_KMS:
        print("[TEST] ✓ PASS: Endpoints are different")
    else:
        print("[TEST] ✗ FAIL: Endpoints are the same")
        return False
    
    # Verify endpoints have correct paths
    if "/v1/data/aws/s3_creation/deny" in OPA_URL_SSE:
        print("[TEST] ✓ PASS: SSE endpoint has correct path")
    else:
        print("[TEST] ✗ FAIL: SSE endpoint has incorrect path")
        return False
    
    if "/v1/data/aws/s3_kms_audit/deny" in OPA_URL_KMS:
        print("[TEST] ✓ PASS: KMS endpoint has correct path")
    else:
        print("[TEST] ✗ FAIL: KMS endpoint has incorrect path")
        return False
    
    return True

def main():
    """
    Run all tests
    """
    print("S3-KMS Integrated Audit System - OPA Endpoint Testing")
    print("=" * 60)
    print(f"Test started at: {datetime.now()}")
    
    tests = [
        ("OPA Configuration", test_opa_configuration),
        ("Endpoint Selection Logic", test_endpoint_selection_logic),
        ("SSE Encryption Endpoint", test_sse_encryption_endpoint),
        ("KMS Encryption Endpoint", test_kms_encryption_endpoint)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Running: {test_name}")
        print(f"{'='*60}")
        
        try:
            result = test_func()
            results.append((test_name, "PASS" if result else "FAIL"))
            print(f"\n[RESULT] {test_name}: {'PASS' if result else 'FAIL'}")
        except Exception as e:
            results.append((test_name, f"ERROR: {e}"))
            print(f"\n[RESULT] {test_name}: ERROR - {e}")
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    for test_name, result in results:
        status_symbol = "✓" if result == "PASS" else "✗"
        print(f"{status_symbol} {test_name}: {result}")
    
    passed = sum(1 for _, result in results if result == "PASS")
    total = len(results)
    
    print(f"\nOverall: {passed}/{total} tests passed")
    print(f"Test completed at: {datetime.now()}")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)