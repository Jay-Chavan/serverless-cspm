import sys
import os
import boto3
from dotenv import load_dotenv

# Add path to finding logic
sys.path.append(os.path.join(os.getcwd(), 'real_time_monitoring', 'aws', 'lambda_deployment', 's3_lambda'))

import mongodb_client
from mongodb_client import MongoDBClient

# Load environment variables
load_dotenv(os.path.join(os.getcwd(), 'csmp-findings-dashboard', 'backend', '.env'))

def cleanup_stale_findings():
    print("Starting cleanup of stale S3 findings...")
    
    # 1. Connect to MongoDB
    mongo = MongoDBClient()
    if not mongo.connect():
        print("Failed to connect to MongoDB.")
        return

    try:
        # 2. Get all S3 findings
        # We need to query distinct bucket names.
        # Since get_recent_findings returns a list, let's just get all and aggregate in python if distinct isn't exposed
        # Or better, just get all findings.
        
        # Access collection directly to get distinct buckets
        if mongo.collection is None:
             print("Collection not initialized.")
             return

        stored_buckets = mongo.collection.distinct('bucket_name')
        print(f"Found findings for {len(stored_buckets)} distinct buckets in MongoDB: {stored_buckets}")

        # 3. Get all actual S3 buckets
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        actual_buckets = {b['Name'] for b in response.get('Buckets', [])}
        print(f"Found {len(actual_buckets)} actual buckets in AWS S3.")

        # 4. Compare and Delete
        stale_buckets = [b for b in stored_buckets if b and b not in actual_buckets]
        
        if not stale_buckets:
            print("No stale findings found. MongoDB is in sync with AWS S3.")
        else:
            print(f"Found {len(stale_buckets)} stale buckets: {stale_buckets}")
            for bucket in stale_buckets:
                print(f"Deleting findings for stale bucket: {bucket}")
                mongo.delete_findings_by_bucket(bucket)

    except Exception as e:
        print(f"Error during cleanup: {e}")
    finally:
        mongo.close_connection()

if __name__ == "__main__":
    cleanup_stale_findings()
