import boto3
import os
import sys
import json
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
env_path = r'd:\Projects\CSPM\serverless-cspm\csmp-findings-dashboard\backend\.env'
load_dotenv(env_path)

print("--- DIAGNOSTIC START ---")

# 1. Verify AWS Connectivity & Bucket State
print("\n[1] Checking S3 Buckets...")
try:
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION', 'ap-south-1')
    )
    
    response = s3.list_buckets()
    demo_buckets = [b for b in response['Buckets'] if b['Name'].startswith('cspm-demo-')]
    
    if not demo_buckets:
        print("  WARNING: No buckets found starting with 'cspm-demo-'")
    else:
        for b in demo_buckets:
            name = b['Name']
            print(f"  Found Bucket: {name}")
            
            # Check Public Access Block
            try:
                pab = s3.get_public_access_block(Bucket=name)
                print(f"    - Public Access Block: {pab['PublicAccessBlockConfiguration']}")
            except Exception as e:
                print(f"    - Public Access Block: Not set (Default - check ACLs)")

            # Check Policy
            try:
                policy = s3.get_bucket_policy(Bucket=name)
                print(f"    - Bucket Policy: Found")
            except Exception as e:
                print(f"    - Bucket Policy: None")

except Exception as e:
    print(f"  ERROR: AWS Connection Failed - {e}")

# 2. Verify MongoDB Connectivity & Data
print("\n[2] Checking MongoDB...")
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    print("  ERROR: MONGO_URI not found in .env")
else:
    try:
        client = MongoClient(mongo_uri)
        # Check connection
        client.admin.command('ping')
        print("  Connection Successful!")
        
        db = client['csmp_findings']
        collection = db['s3_audit_findings']
        
        count = collection.count_documents({})
        print(f"  Total Findings in 's3_audit_findings': {count}")
        
        # Check for recent findings
        recent = list(collection.find().sort('timestamp', -1).limit(3))
        if recent:
            print("  Latest 3 Findings:")
            for doc in recent:
                print(f"    - Full Document: {json.dumps(doc, default=str, indent=2)}")
        else:
            print("  No findings found. Database is accessible but empty.")
            
    except Exception as e:
        print(f"  ERROR: MongoDB Connection Failed - {str(e)}")

print("\n--- DIAGNOSTIC END ---")
