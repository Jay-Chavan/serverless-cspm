#!/usr/bin/env python3
"""
Test script to demonstrate the comprehensive S3 security audit functionality.
This script shows how the new audit function collects all S3 security properties
and creates a comprehensive input JSON for OPA evaluation.
"""

import boto3
import json
from BucketACLS import get_s3_bucket_security_config, audit_bucket_security
from opa_client import send_opa_request

def test_bucket_config_collection(bucket_name, region="us-east-1"):
    """
    Test function to demonstrate comprehensive S3 security configuration collection.
    
    Args:
        bucket_name: Name of the S3 bucket to test
        region: AWS region (default: us-east-1)
    """
    print(f"Testing comprehensive S3 security audit for bucket: {bucket_name}")
    print("=" * 60)
    
    try:
        # Initialize S3 client
        s3_client = boto3.client('s3', region_name=region)
        
        # Collect comprehensive security configuration
        print("\n1. Collecting comprehensive S3 security configuration...")
        bucket_config = get_s3_bucket_security_config(bucket_name, s3_client)
        
        # Add sample tagset
        bucket_config["tagset"] = [
            {"Key": "Environment", "Value": "Production"},
            {"Key": "Owner", "Value": "SecurityTeam"}
        ]
        
        print("\n2. Complete Security Configuration JSON:")
        print(json.dumps(bucket_config, indent=2, default=str))
        
        print("\n3. Key Security Properties Summary:")
        print(f"   • Bucket Name: {bucket_config['bucket_name']}")
        print(f"   • Encryption: {bucket_config['encryption']}")
        print(f"   • Ownership: {bucket_config['bucket_ownership']}")
        print(f"   • ACLs Enabled: {bucket_config['acls_enabled']}")
        print(f"   • Public Access: {bucket_config['public_access']}")
        print(f"   • Versioning: {bucket_config['versioning']}")
        print(f"   • MFA Delete: {bucket_config['mfa_delete']}")
        print(f"   • Bucket Policy: {'Present' if bucket_config['bucket_policy'] else 'None'}")
        print(f"   • Logging: {bucket_config['logging']}")
        print(f"   • Notifications: {bucket_config['notification']}")
        
        print("\n4. This configuration will be sent to OPA for policy evaluation.")
        
        return bucket_config
        
    except Exception as e:
        print(f"Error during testing: {e}")
        return None

def test_full_audit(bucket_name, account_id, region="us-east-1"):
    """
    Test the full audit process including OPA evaluation and Security Hub finding generation.
    
    Args:
        bucket_name: Name of the S3 bucket to audit
        account_id: AWS account ID
        region: AWS region
    """
    print(f"\nTesting full security audit for bucket: {bucket_name}")
    print("=" * 60)
    
    try:
        # Sample tagset
        tagset = [
            {"Key": "Environment", "Value": "Production"},
            {"Key": "Owner", "Value": "SecurityTeam"}
        ]
        
        # Run comprehensive audit
        finding = audit_bucket_security(
            bucket_name=bucket_name,
            accountId=account_id,
            region=region,
            tagset=tagset
        )
        
        if finding:
            print("\nSecurity finding generated successfully!")
            print("Finding includes comprehensive S3 security details in Security Hub format.")
        else:
            print("\nNo security issues found - bucket is compliant.")
            
        return finding
        
    except Exception as e:
        print(f"Error during full audit: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    BUCKET_NAME = "jayserverlesscspmfilesbucket"  # Replace with actual bucket name
    ACCOUNT_ID = "554739427981"  # Replace with actual account ID
    REGION = "us-east-1"  # Replace with actual region
    
    print("S3 Comprehensive Security Audit Test")
    print("=====================================")
    print("\nThis script demonstrates the new comprehensive S3 security audit functionality.")
    print("It collects all security-related properties and creates detailed input for OPA.")
    
    # Test configuration collection
    config = test_bucket_config_collection(BUCKET_NAME, REGION)
    
    # Test full audit (uncomment to test with actual OPA server)
    # finding = test_full_audit(BUCKET_NAME, ACCOUNT_ID, REGION)
    
    print("\n" + "=" * 60)
    print("Test completed. The new audit function now checks:")
    print("• Encryption (SSE-S3, SSE-KMS with key ID, or none)")
    print("• Bucket ownership controls and ACL settings")
    print("• Public access block configuration")
    print("• Versioning and MFA delete settings")
    print("• Bucket policy (full policy document)")
    print("• Access logging configuration")
    print("• Event notification configuration")
    print("\nAll this data is sent to OPA for comprehensive policy evaluation.")