import boto3
import time
import uuid
import json

s3 = boto3.client('s3')
region = 'ap-south-1'  # Update if needed

def create_bucket_name(prefix):
    return f"{prefix}-{str(uuid.uuid4())[:8]}"

def demo():
    print("=== CSPM Real-Time Demonstration ===")
    
    # --- Test Case 1 ---
    print("\n[Test Case 1] Detection of New Insecure Bucket")
    bucket_1 = create_bucket_name("cspm-demo-public")
    print(f"Creating bucket: {bucket_1}")
    s3.create_bucket(Bucket=bucket_1, CreateBucketConfiguration={'LocationConstraint': region})
    
    print("Applying PUBLIC ACL/Policy...")
    # Removing public access block to allow public policy
    s3.delete_public_access_block(Bucket=bucket_1)
    # Applying public policy
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_1}/*"
        }]
    }
    s3.put_bucket_policy(Bucket=bucket_1, Policy=json.dumps(public_policy))
    
    print(f"✅ ACTION COMPLETE: Bucket '{bucket_1}' created and made public.")
    input(">>> CHECK DASHBOARD. Press Enter when finding appears to continue...")


    # --- Test Case 2 ---
    print("\n[Test Case 2] Security Drift (Modification)")
    bucket_2 = create_bucket_name("cspm-demo-drift")
    print(f"Creating SECURE bucket: {bucket_2}")
    s3.create_bucket(Bucket=bucket_2, CreateBucketConfiguration={'LocationConstraint': region})
    
    print("Waiting 10s...")
    time.sleep(10)
    print("✅ ACTION COMPLETE: Secure bucket created. Verify NO finding appears.")
    input(">>> CHECK DASHBOARD. Press Enter to simulate ATTACK/DRIFT...")
    
    print(f"Modifying '{bucket_2}' to be PUBLIC...")
    s3.delete_public_access_block(Bucket=bucket_2)
    s3.put_bucket_policy(Bucket=bucket_2, Policy=json.dumps(public_policy))
    
    print(f"✅ ACTION COMPLETE: Bucket '{bucket_2}' is now compromised.")
    input(">>> CHECK DASHBOARD. Press Enter when finding appears...")


    # --- Test Case 3 ---
    print("\n[Test Case 3] Real-time Cleanup")
    print(f"Deleting bucket '{bucket_1}'...")
    # Delete objects first
    s3.delete_bucket_policy(Bucket=bucket_1)
    s3.delete_bucket(Bucket=bucket_1)
    
    print(f"✅ ACTION COMPLETE: Bucket '{bucket_1}' deleted.")
    input(">>> CHECK DASHBOARD. Finding should disappear. Press Enter to finish...")
    
    # Cleanup bucket 2
    print("Cleaning up remaining resources...")
    try:
        s3.delete_bucket_policy(Bucket=bucket_2)
        s3.delete_bucket(Bucket=bucket_2)
        print(f"Deleted {bucket_2}")
    except:
        pass
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    demo()
