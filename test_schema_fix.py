
import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv
from pymongo import MongoClient

# Add the lambda directory to the path so we can import mongodb_client
sys.path.append(r'd:\Projects\CSPM\serverless-cspm\real_time_monitoring\aws\lambda_deployment\s3_lambda')

from mongodb_client import store_finding_to_mongodb

# Load env variables for MONGO_URI
env_path = r'd:\Projects\CSPM\serverless-cspm\csmp-findings-dashboard\backend\.env'
load_dotenv(env_path)

def verify_schema_fix():
    print("--- VERIFICATION START ---")
    
    bucket_name = "schema-verification-bucket"
    finding_id = f"test-schema-{datetime.now().timestamp()}"
    
    # Mock Security Hub finding structure
    mock_finding = {
        "Findings": [{
            "Id": finding_id,
            "Severity": {"Label": "HIGH"},
            "Title": "Schema Verification Test",
            "Description": "Testing if resource_name, service, and status are added correctly.",
            "AwsAccountId": "123456789012",
            "Resources": [{"Region": "us-east-1"}],
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "RecordState": "ACTIVE"
        }]
    }
    
    print(f"[INFO] Storing test finding for bucket: {bucket_name}")
    doc_id = store_finding_to_mongodb(mock_finding, bucket_name)
    
    if not doc_id:
        print("[ERROR] Failed to store finding.")
        return False
        
    print(f"[INFO] Finding stored with ID: {doc_id}")
    
    # Verify the stored document
    mongo_uri = os.getenv('MONGO_URI')
    client = MongoClient(mongo_uri)
    db = client['csmp_findings']
    collection = db['s3_audit_findings']
    
    from bson.objectid import ObjectId
    doc = collection.find_one({"_id": ObjectId(doc_id)})
    
    if not doc:
        print("[ERROR] Could not retrieve stored document.")
        return False
        
    print(f"[INFO] Retrieved document: {json.dumps(doc, default=str, indent=2)}")
    
    # Check for missing fields
    missing_fields = []
    if 'resource_name' not in doc: missing_fields.append('resource_name')
    if 'service' not in doc: missing_fields.append('service')
    if 'status' not in doc: missing_fields.append('status')
    
    if missing_fields:
        print(f"[FAIL] Missing fields: {missing_fields}")
        return False
        
    # Check values
    if doc['resource_name'] != bucket_name:
        print(f"[FAIL] resource_name mismatch. Expected: {bucket_name}, Got: {doc['resource_name']}")
        return False
    if doc['service'] != 'S3':
        print(f"[FAIL] service mismatch. Expected: S3, Got: {doc['service']}")
        return False
    if doc['status'] != 'Open': # Should be Open because Compliance Status is FAILED
        print(f"[FAIL] status mismatch. Expected: Open, Got: {doc['status']}")
        return False
        
    print("[SUCCESS] All fields present and correct!")
    
    # Cleanup
    collection.delete_one({"_id": ObjectId(doc_id)})
    print("[INFO] Cleanup: Test finding deleted.")
    
    return True

if __name__ == "__main__":
    verify_schema_fix()
