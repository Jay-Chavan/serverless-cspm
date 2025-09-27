#!/usr/bin/env python3
"""
Test script for MongoDB integration with S3 audit findings
"""

import json
import sys
import os
from datetime import datetime, timezone

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mongodb_client import MongoDBClient, store_finding_to_mongodb

def create_sample_finding():
    """
    Create a sample Security Hub finding for testing
    """
    return {
        "Findings": [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "arn:aws:s3:::test-bucket/S3BucketSecurityAudit",
                "ProductArn": "arn:aws:securityhub:us-east-1::123456789012:product/123456789012/default",
                "GeneratorId": "csmp-s3-security-audit",
                "AwsAccountId": "123456789012",
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "CreatedAt": datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
                "UpdatedAt": datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
                "Severity": {
                    "Label": "HIGH",
                    "Normalized": 70
                },
                "Title": "S3 Bucket Security Configuration Issues Detected",
                "Description": "S3 bucket 'test-bucket' has security configuration issues. Issues found: No encryption, Public ACLs allowed, Versioning disabled. Policy evaluation reason: Bucket lacks proper security controls",
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": "arn:aws:s3:::test-bucket",
                        "Partition": "aws",
                        "Region": "us-east-1",
                        "Details": {
                            "AwsS3Bucket": {
                                "Name": "test-bucket",
                                "OwnerId": "123456789012",
                                "OwnerName": "test-owner",
                                "CreationDate": "2024-01-01T00:00:00Z",
                                "ServerSideEncryptionConfiguration": {
                                    "Rules": []
                                },
                                "PublicAccessBlockConfiguration": {
                                    "block_public_acls": False,
                                    "block_public_policy": False,
                                    "ignore_public_acls": False,
                                    "restrict_public_buckets": False
                                },
                                "BucketVersioningConfiguration": {
                                    "Status": "Suspended",
                                    "MfaDelete": "Disabled"
                                }
                            }
                        }
                    }
                ],
                "RecordState": "ACTIVE",
                "WorkflowState": "NEW",
                "Compliance": {
                    "Status": "FAILED",
                    "SecurityControlId": "S3.1",
                    "AssociatedStandards": [
                        {
                            "StandardsId": "aws-foundational-security-standard"
                        }
                    ]
                },
                "UserDefinedFields": {
                    "FindingId": "test-finding-12345",
                    "S3Configuration": json.dumps({
                        "bucket_name": "test-bucket",
                        "encryption": None,
                        "public_access_block": {
                            "block_public_acls": False,
                            "block_public_policy": False,
                            "ignore_public_acls": False,
                            "restrict_public_buckets": False
                        },
                        "versioning": {
                            "status": "Suspended",
                            "mfa_delete": "Disabled"
                        }
                    })
                }
            }
        ]
    }

def test_mongodb_connection():
    """
    Test MongoDB connection
    """
    print("="*60)
    print("Testing MongoDB Connection")
    print("="*60)
    
    mongo_client = MongoDBClient()
    
    if mongo_client.connect():
        print("✅ Successfully connected to MongoDB cluster")
        mongo_client.close_connection()
        return True
    else:
        print("❌ Failed to connect to MongoDB cluster")
        return False

def test_store_finding():
    """
    Test storing a finding in MongoDB
    """
    print("\n" + "="*60)
    print("Testing Store Finding")
    print("="*60)
    
    sample_finding = create_sample_finding()
    bucket_name = "test-bucket"
    
    print(f"Storing sample finding for bucket: {bucket_name}")
    document_id = store_finding_to_mongodb(sample_finding, bucket_name)
    
    if document_id:
        print(f"✅ Successfully stored finding with ID: {document_id}")
        return document_id
    else:
        print("❌ Failed to store finding")
        return None

def test_retrieve_findings():
    """
    Test retrieving findings from MongoDB
    """
    print("\n" + "="*60)
    print("Testing Retrieve Findings")
    print("="*60)
    
    mongo_client = MongoDBClient()
    
    if mongo_client.connect():
        # Test retrieving findings by bucket
        bucket_findings = mongo_client.get_findings_by_bucket("test-bucket", limit=5)
        print(f"✅ Retrieved {len(bucket_findings)} findings for test-bucket")
        
        # Test retrieving recent findings
        recent_findings = mongo_client.get_recent_findings(limit=10)
        print(f"✅ Retrieved {len(recent_findings)} recent findings")
        
        mongo_client.close_connection()
        return True
    else:
        print("❌ Failed to connect to MongoDB for retrieval test")
        return False

def main():
    """
    Main test function
    """
    print("MongoDB Integration Test Suite")
    print("="*60)
    
    # Test 1: Connection
    connection_success = test_mongodb_connection()
    
    if not connection_success:
        print("\n❌ Connection test failed. Exiting...")
        return False
    
    # Test 2: Store Finding
    document_id = test_store_finding()
    
    if not document_id:
        print("\n❌ Store finding test failed. Exiting...")
        return False
    
    # Test 3: Retrieve Findings
    retrieval_success = test_retrieve_findings()
    
    if not retrieval_success:
        print("\n❌ Retrieve findings test failed.")
        return False
    
    print("\n" + "="*60)
    print("✅ All MongoDB integration tests passed!")
    print("="*60)
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)