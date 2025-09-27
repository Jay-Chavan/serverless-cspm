#!/usr/bin/env python3
"""
Test script for integrated S3 and KMS security audit functionality.
This demonstrates how S3 buckets with KMS encryption are audited for both S3 and KMS security issues.
"""

import boto3
import json
from BucketACLS import audit_bucket_security
import sys
import os

# Import KMS API client for communicating with KMS Lambda
from kms_api_client import get_kms_client

def test_integrated_s3_kms_audit():
    """
    Test the integrated S3 and KMS security audit.
    This function demonstrates how S3 buckets with KMS encryption
    trigger additional KMS security checks.
    """
    # Example configuration - replace with your actual values
    bucket_name = "example-bucket-with-kms"
    account_id = "123456789012"
    region = "us-east-1"
    
    print("=" * 80)
    print("INTEGRATED S3 AND KMS SECURITY AUDIT TEST")
    print("=" * 80)
    print(f"Testing bucket: {bucket_name}")
    print(f"Account ID: {account_id}")
    print(f"Region: {region}")
    print("\n")
    
    try:
        # Perform the integrated audit
        print("[INFO] Starting integrated S3 security audit...")
        print("[INFO] This will automatically check KMS keys if the bucket uses KMS encryption")
        
        result = audit_bucket_security(
            bucket_name=bucket_name,
            account_id=account_id,
            region=region
        )
        
        if result:
            print("\n" + "=" * 60)
            print("AUDIT RESULTS")
            print("=" * 60)
            
            # Check if this is an S3 finding or KMS finding
            finding = result["Findings"][0]
            resource_type = finding["Resources"][0]["Type"]
            
            if resource_type == "AwsS3Bucket":
                print("[RESULT] S3 Security Finding Generated")
                print(f"[RESULT] Finding ID: {finding['Id']}")
                print(f"[RESULT] Severity: {finding['Severity']['Label']}")
                print(f"[RESULT] Title: {finding['Title']}")
                print(f"[RESULT] Description: {finding['Description']}")
                
                # Check for linked KMS finding
                user_fields = finding.get("UserDefinedFields", {})
                if "LinkedKMSFindingId" in user_fields:
                    print(f"[RESULT] Linked KMS Finding ID: {user_fields['LinkedKMSFindingId']}")
                    print(f"[RESULT] KMS Security Status: {user_fields['KMSSecurityStatus']}")
                    
                    # Show encryption details
                    encryption_config = finding["Resources"][0]["Details"]["AwsS3Bucket"]["ServerSideEncryptionConfiguration"]
                    if encryption_config["Rules"]:
                        encryption_rule = encryption_config["Rules"][0]["ApplyServerSideEncryptionByDefault"]
                        print(f"[RESULT] Encryption Algorithm: {encryption_rule.get('SSEAlgorithm')}")
                        print(f"[RESULT] KMS Key ID: {encryption_rule.get('KMSMasterKeyID')}")
                        print(f"[RESULT] KMS Security Status: {encryption_rule.get('KMSSecurityStatus')}")
                
            elif resource_type == "AwsKmsKey":
                print("[RESULT] KMS Security Finding Generated (S3 was compliant)")
                print(f"[RESULT] Finding ID: {finding['Id']}")
                print(f"[RESULT] Severity: {finding['Severity']['Label']}")
                print(f"[RESULT] Title: {finding['Title']}")
                print(f"[RESULT] Description: {finding['Description']}")
                
                # Show KMS key details
                kms_details = finding["Resources"][0]["Details"]["AwsKmsKey"]
                print(f"[RESULT] KMS Key ID: {kms_details.get('KeyId')}")
                print(f"[RESULT] Key State: {kms_details.get('KeyState')}")
                print(f"[RESULT] Key Rotation Enabled: {kms_details.get('KeyRotationEnabled')}")
            
            print("\n[INFO] Full finding object:")
            print(json.dumps(result, indent=2, default=str))
            
        else:
            print("\n[RESULT] No security findings - bucket and KMS key (if used) are compliant")
            
    except Exception as e:
        print(f"\n[ERROR] Audit failed: {e}")
        import traceback
        traceback.print_exc()

def test_kms_only_audit():
    """
    Test KMS-only security audit for a specific KMS key.
    """
    # Example configuration - replace with your actual values
    kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    account_id = "123456789012"
    region = "us-east-1"
    
    print("\n" + "=" * 80)
    print("KMS-ONLY SECURITY AUDIT TEST")
    print("=" * 80)
    print(f"Testing KMS key: {kms_key_id}")
    print(f"Account ID: {account_id}")
    print(f"Region: {region}")
    print("\n")
    
    try:
        kms_client = get_kms_client()
        result = kms_client.audit_kms_key_security(
            key_id=kms_key_id,
            account_id=account_id,
            region=region
        )
        
        if result:
            print("\n" + "=" * 60)
            print("KMS AUDIT RESULTS")
            print("=" * 60)
            
            finding = result["Findings"][0]
            print(f"[RESULT] Finding ID: {finding['Id']}")
            print(f"[RESULT] Severity: {finding['Severity']['Label']}")
            print(f"[RESULT] Title: {finding['Title']}")
            print(f"[RESULT] Description: {finding['Description']}")
            
            # Show KMS key details
            kms_details = finding["Resources"][0]["Details"]["AwsKmsKey"]
            print(f"[RESULT] KMS Key ID: {kms_details.get('KeyId')}")
            print(f"[RESULT] Key State: {kms_details.get('KeyState')}")
            print(f"[RESULT] Key Usage: {kms_details.get('KeyUsage')}")
            print(f"[RESULT] Key Manager: {kms_details.get('KeyManager')}")
            print(f"[RESULT] Key Rotation Enabled: {kms_details.get('KeyRotationEnabled')}")
            print(f"[RESULT] Multi-Region: {kms_details.get('MultiRegion')}")
            print(f"[RESULT] Number of Aliases: {len(kms_details.get('Aliases', []))}")
            print(f"[RESULT] Number of Grants: {kms_details.get('GrantsCount', 0)}")
            
            print("\n[INFO] Full KMS finding object:")
            print(json.dumps(result, indent=2, default=str))
            
        else:
            print("\n[RESULT] No KMS security findings - key is compliant")
            
    except Exception as e:
        print(f"\n[ERROR] KMS audit failed: {e}")
        import traceback
        traceback.print_exc()

def show_integration_workflow():
    """
    Display the integration workflow between S3 and KMS audits.
    """
    print("\n" + "=" * 80)
    print("S3-KMS INTEGRATION WORKFLOW")
    print("=" * 80)
    
    workflow = """
    1. S3 Audit Starts
       ├── Collect S3 bucket security configuration
       ├── Check encryption settings
       └── If KMS encryption detected:
           ├── Extract KMS key ID
           ├── Perform KMS security audit
           ├── Update S3 config with KMS security status
           └── Link KMS finding ID to S3 finding
    
    2. OPA Policy Evaluation
       ├── Send comprehensive S3 config (including KMS status) to OPA
       ├── OPA evaluates S3 security posture
       └── Consider KMS security status in evaluation
    
    3. Finding Generation
       ├── Generate S3 finding if issues found
       ├── Include KMS security status in S3 finding
       ├── Link to KMS finding ID if KMS issues exist
       └── Return appropriate finding (S3, KMS, or both)
    
    4. Security Hub Integration
       ├── S3 findings reference linked KMS findings
       ├── KMS findings can be traced back to S3 buckets
       └── Comprehensive security posture visibility
    """
    
    print(workflow)
    
    print("\nKEY INTEGRATION POINTS:")
    print("- S3 encryption field shows 'insecure kms key' when KMS issues found")
    print("- S3 finding includes 'LinkedKMSFindingId' in UserDefinedFields")
    print("- KMS security status included in S3 ServerSideEncryptionConfiguration")
    print("- Both findings can be ingested into AWS Security Hub")
    print("- Enables tracking of vulnerable resources across services")

if __name__ == "__main__":
    print("AWS S3-KMS Integrated Security Audit Test")
    print("This script demonstrates the integrated security audit functionality.")
    print("\nMake sure to:")
    print("1. Configure AWS credentials")
    print("2. Update bucket names and KMS key IDs in the test functions")
    print("3. Ensure OPA server is running and accessible")
    print("4. Have appropriate AWS permissions for S3 and KMS operations")
    
    # Show the integration workflow
    show_integration_workflow()
    
    # Uncomment the following lines to run actual tests
    # (Make sure to update the configuration values first)
    
    # print("\n" + "="*80)
    # print("RUNNING TESTS")
    # print("="*80)
    
    # Test integrated S3-KMS audit
    # test_integrated_s3_kms_audit()
    
    # Test KMS-only audit
    # test_kms_only_audit()
    
    print("\n[INFO] Test script completed. Uncomment test function calls to run actual audits.")