#!/usr/bin/env python3
"""
Sample Data Population Script for CSMP Findings Dashboard
This script populates the MongoDB collection with realistic S3 security findings
"""

import os
from datetime import datetime, timedelta
import random
from pymongo import MongoClient
from bson.objectid import ObjectId

# MongoDB connection
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = os.getenv('DATABASE_NAME', 'csmp_findings')
COLLECTION_NAME = os.getenv('COLLECTION_NAME', 'security_findings')

def connect_to_mongodb():
    """Connect to MongoDB and return collection"""
    try:
        client = MongoClient(MONGO_URI)
        db = client[DATABASE_NAME]
        collection = db[COLLECTION_NAME]
        print(f"Connected to MongoDB: {DATABASE_NAME}")
        return collection
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return None

def generate_sample_findings():
    """Generate sample S3 security findings"""
    
    # Sample AWS account and region data
    aws_accounts = ['123456789012', '987654321098', '456789123456']
    regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
    
    # Sample bucket names
    bucket_names = [
        'company-data-backup', 'user-uploads-prod', 'analytics-logs',
        'static-website-assets', 'database-backups', 'application-logs',
        'media-files-storage', 'config-files-bucket', 'temp-processing-data'
    ]
    
    findings = []
    
    # Generate S3 ACL enabled findings
    for i in range(5):
        bucket_name = random.choice(bucket_names) + f"-{random.randint(100, 999)}"
        account_id = random.choice(aws_accounts)
        region = random.choice(regions)
        
        finding = {
            "_id": ObjectId(),
            "finding_id": f"s3-acl-{random.randint(10000, 99999)}",
            "title": "S3 Bucket ACLs Enabled",
            "description": f"S3 bucket '{bucket_name}' has Access Control Lists (ACLs) enabled, which may allow unintended access permissions.",
            "severity": random.choice(["Medium", "High"]),
            "service": "S3",
            "resource_id": f"arn:aws:s3:::{bucket_name}",
            "resource_name": bucket_name,
            "account_id": account_id,
            "region": region,
            "status": random.choice(["Open", "In Progress", "Resolved"]),
            "compliance_standards": ["AWS Config", "CIS AWS Foundations"],
            "remediation": {
                "description": "Disable S3 bucket ACLs and use bucket policies for access control",
                "steps": [
                    "Navigate to S3 console",
                    f"Select bucket '{bucket_name}'",
                    "Go to Permissions tab",
                    "Edit Object Ownership settings",
                    "Select 'Bucket owner enforced' to disable ACLs",
                    "Review and update bucket policies as needed"
                ],
                "aws_cli_command": f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} --ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]"
            },
            "risk_score": random.randint(60, 85),
            "first_detected": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
            "last_updated": (datetime.utcnow() - timedelta(hours=random.randint(1, 24))).isoformat(),
            "tags": {
                "Environment": random.choice(["Production", "Staging", "Development"]),
                "Team": random.choice(["DevOps", "Security", "Data"]),
                "CostCenter": f"CC-{random.randint(1000, 9999)}"
            },
            "metadata": {
                "scan_type": "Configuration Assessment",
                "scanner": "AWS Config",
                "rule_name": "s3-bucket-acl-prohibited",
                "finding_type": "Security"
            }
        }
        findings.append(finding)
    
    # Generate S3 public access enabled findings
    for i in range(6):
        bucket_name = random.choice(bucket_names) + f"-{random.randint(100, 999)}"
        account_id = random.choice(aws_accounts)
        region = random.choice(regions)
        
        public_access_types = [
            "Block Public ACLs: False",
            "Ignore Public ACLs: False", 
            "Block Public Policy: False",
            "Restrict Public Buckets: False"
        ]
        
        finding = {
            "_id": ObjectId(),
            "finding_id": f"s3-public-{random.randint(10000, 99999)}",
            "title": "S3 Bucket Public Access Enabled",
            "description": f"S3 bucket '{bucket_name}' has public access settings enabled, potentially exposing data to unauthorized users.",
            "severity": random.choice(["High", "Critical"]),
            "service": "S3",
            "resource_id": f"arn:aws:s3:::{bucket_name}",
            "resource_name": bucket_name,
            "account_id": account_id,
            "region": region,
            "status": random.choice(["Open", "In Progress"]),
            "compliance_standards": ["AWS Config", "CIS AWS Foundations", "PCI DSS"],
            "remediation": {
                "description": "Block all public access to the S3 bucket",
                "steps": [
                    "Navigate to S3 console",
                    f"Select bucket '{bucket_name}'",
                    "Go to Permissions tab",
                    "Click 'Edit' on Block public access settings",
                    "Check all four options to block public access",
                    "Save changes and confirm"
                ],
                "aws_cli_command": f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            },
            "risk_score": random.randint(80, 95),
            "first_detected": (datetime.utcnow() - timedelta(days=random.randint(1, 45))).isoformat(),
            "last_updated": (datetime.utcnow() - timedelta(hours=random.randint(1, 12))).isoformat(),
            "details": {
                "public_access_settings": random.choice(public_access_types),
                "bucket_policy": "Present" if random.choice([True, False]) else "None",
                "website_hosting": "Enabled" if random.choice([True, False]) else "Disabled"
            },
            "tags": {
                "Environment": random.choice(["Production", "Staging", "Development"]),
                "Team": random.choice(["DevOps", "Security", "Data", "Frontend"]),
                "CostCenter": f"CC-{random.randint(1000, 9999)}",
                "Criticality": "High"
            },
            "metadata": {
                "scan_type": "Configuration Assessment",
                "scanner": "AWS Config",
                "rule_name": "s3-bucket-public-access-prohibited",
                "finding_type": "Security"
            }
        }
        findings.append(finding)
    
    # Add some additional diverse findings
    additional_findings = [
        {
            "_id": ObjectId(),
            "finding_id": f"s3-encryption-{random.randint(10000, 99999)}",
            "title": "S3 Bucket Encryption Not Enabled",
            "description": f"S3 bucket 'logs-bucket-{random.randint(100, 999)}' does not have server-side encryption enabled.",
            "severity": "Medium",
            "service": "S3",
            "resource_id": f"arn:aws:s3:::logs-bucket-{random.randint(100, 999)}",
            "resource_name": f"logs-bucket-{random.randint(100, 999)}",
            "account_id": random.choice(aws_accounts),
            "region": random.choice(regions),
            "status": "Open",
            "compliance_standards": ["AWS Config", "SOC 2"],
            "risk_score": random.randint(50, 70),
            "first_detected": (datetime.utcnow() - timedelta(days=random.randint(5, 20))).isoformat(),
            "last_updated": (datetime.utcnow() - timedelta(hours=random.randint(6, 48))).isoformat(),
            "tags": {
                "Environment": "Production",
                "Team": "Security",
                "CostCenter": f"CC-{random.randint(1000, 9999)}"
            },
            "metadata": {
                "scan_type": "Configuration Assessment",
                "scanner": "AWS Config",
                "rule_name": "s3-bucket-server-side-encryption-enabled",
                "finding_type": "Security"
            }
        },
        {
            "_id": ObjectId(),
            "finding_id": f"s3-versioning-{random.randint(10000, 99999)}",
            "title": "S3 Bucket Versioning Not Enabled",
            "description": f"S3 bucket 'backup-storage-{random.randint(100, 999)}' does not have versioning enabled.",
            "severity": "Low",
            "service": "S3",
            "resource_id": f"arn:aws:s3:::backup-storage-{random.randint(100, 999)}",
            "resource_name": f"backup-storage-{random.randint(100, 999)}",
            "account_id": random.choice(aws_accounts),
            "region": random.choice(regions),
            "status": "Resolved",
            "compliance_standards": ["AWS Config"],
            "risk_score": random.randint(30, 50),
            "first_detected": (datetime.utcnow() - timedelta(days=random.randint(10, 60))).isoformat(),
            "last_updated": (datetime.utcnow() - timedelta(days=random.randint(1, 5))).isoformat(),
            "tags": {
                "Environment": "Production",
                "Team": "Data",
                "CostCenter": f"CC-{random.randint(1000, 9999)}"
            },
            "metadata": {
                "scan_type": "Configuration Assessment",
                "scanner": "AWS Config",
                "rule_name": "s3-bucket-versioning-enabled",
                "finding_type": "Security"
            }
        }
    ]
    
    findings.extend(additional_findings)
    return findings

def populate_database():
    """Populate MongoDB with sample findings"""
    collection = connect_to_mongodb()
    if collection is None:
        return False
    
    # Clear existing data (optional - comment out if you want to keep existing data)
    print("Clearing existing findings...")
    collection.delete_many({})
    
    # Generate and insert sample findings
    print("Generating sample findings...")
    findings = generate_sample_findings()
    
    print(f"Inserting {len(findings)} sample findings...")
    result = collection.insert_many(findings)
    
    print(f"Successfully inserted {len(result.inserted_ids)} findings into MongoDB")
    
    # Print summary
    print("\n=== Summary ===")
    total_count = collection.count_documents({})
    severity_counts = {}
    service_counts = {}
    status_counts = {}
    
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = collection.count_documents({"severity": severity})
        if count > 0:
            severity_counts[severity] = count
    
    for service in ["S3", "EC2", "IAM"]:
        count = collection.count_documents({"service": service})
        if count > 0:
            service_counts[service] = count
    
    for status in ["Open", "In Progress", "Resolved"]:
        count = collection.count_documents({"status": status})
        if count > 0:
            status_counts[status] = count
    
    print(f"Total findings: {total_count}")
    print(f"By severity: {severity_counts}")
    print(f"By service: {service_counts}")
    print(f"By status: {status_counts}")
    
    return True

if __name__ == "__main__":
    print("CSMP Findings Dashboard - Sample Data Population")
    print("=" * 50)
    
    success = populate_database()
    if success:
        print("\n✅ Sample data population completed successfully!")
        print("You can now view the findings in your dashboard at http://localhost:5173/")
    else:
        print("\n❌ Failed to populate sample data")