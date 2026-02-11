import sys
import os
from typing import List, Dict, Any, cast
from dotenv import load_dotenv

# Add path to finding logic
# The following import block handles dynamic path resolution for local execution
sys.path.append(os.path.join(os.getcwd(), 'real_time_monitoring', 'aws', 'lambda_deployment', 's3_lambda'))

try:
    import mongodb_client  # type: ignore
    from mongodb_client import MongoDBClient  # type: ignore
except ImportError:
    print("Error: Could not import mongodb_client. Ensure the path is correct.")
    sys.exit(1)

# Load environment variables
load_dotenv(os.path.join(os.getcwd(), 'csmp-findings-dashboard', 'backend', '.env'))

def deduplicate_findings() -> None:
    print("Starting deduplication of S3 findings...")
    
    mongo = MongoDBClient()
    if not mongo.connect():
        print("Failed to connect to MongoDB.")
        return

    try:
        if mongo.collection is None:
             print("Collection not initialized.")
             return

        # 1. Get all buckets with findings
        # Explicitly cast collection to Any to bypass linter inference issues with dynamic import
        collection: Any = mongo.collection
        buckets: List[str] = collection.distinct('bucket_name')
        print(f"Found findings for {len(buckets)} buckets.")

        total_deleted: int = 0

        for bucket in buckets:
            # 2. Get all findings for this bucket, sorted by timestamp (newest first)
            # Use cast to help static analysis understand the return type is a list of dicts
            cursor = collection.find({'bucket_name': bucket}).sort('timestamp', -1) # type: ignore
            findings: List[Dict[str, Any]] = list(cursor)
            
            if len(findings) > 1:
                print(f"Bucket '{bucket}' has {len(findings)} findings. Keeping the latest one.")
                
                # Keep the first one (latest), delete the rest
                # Linter workaround: slice explicitly or iterate
                duplicate_ids: List[str] = []
                # Skip first element
                for i in range(1, len(findings)):
                    if '_id' in findings[i]:
                        duplicate_ids.append(findings[i]['_id'])
                
                if duplicate_ids:
                    result = collection.delete_many({'_id': {'$in': duplicate_ids}}) # type: ignore
                    deleted_count: int = int(result.deleted_count)
                    print(f"  Deleted {deleted_count} duplicates for '{bucket}'.")
                    total_deleted += deleted_count # type: ignore
            else:
                pass

        print(f"\nDeduplication complete. Total findings removed: {total_deleted}")

    except Exception as e:
        print(f"Error during deduplication: {e}")
    finally:
        # Ensure connection is closed even if errors occur
        try:
            mongo.close_connection()
        except Exception:
            pass

if __name__ == "__main__":
    deduplicate_findings()
