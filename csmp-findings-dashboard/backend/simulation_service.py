
import boto3
import uuid
import time
import logging
import threading
from botocore.exceptions import ClientError
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
# Prefix to ensure we ONLY touch our own demo buckets
DEMO_BUCKET_PREFIX = "cspm-demo-"
# Region for simulation
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

class SimulationService:
    def __init__(self):
        self.s3_client = boto3.client("s3", region_name=AWS_REGION)
        self.active_simulations = {}

    def _generate_bucket_name(self):
        """Generate a random bucket name with the safe prefix"""
        return f"{DEMO_BUCKET_PREFIX}{uuid.uuid4().hex[:8]}"

    def create_vulnerable_s3_bucket(self):
        """
        Creates a publicly accessible S3 bucket to simulate a security vulnerability.
        Returns the bucket name if successful.
        """
        bucket_name = self._generate_bucket_name()
        logger.info(f"Starting simulation: Creating vulnerable bucket {bucket_name}")

        try:
            # 1. Create the bucket
            if AWS_REGION == "us-east-1":
                self.s3_client.create_bucket(Bucket=bucket_name)
            else:
                self.s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
                )
            
            # 2. Disable "Block Public Access" (this enables the *possibility* of public access)
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            )

            # 3. Add a public bucket policy (The actual vulnerability)
            public_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    }
                ],
            }
            # Add a slight delay to ensure the PAB removal has propagated
            time.sleep(2)
            
            import json
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(public_policy)
            )

            logger.info(f"Successfully created vulnerable bucket: {bucket_name}")
            
            # Track this simulation
            self.active_simulations[bucket_name] = {
                "created_at": time.time(),
                "status": "active"
            }
            
            # Schedule auto-cleanup
            self._schedule_cleanup(bucket_name)
            
            return {
                "success": True, 
                "message": f"Vulnerable bucket '{bucket_name}' created.",
                "resource_id": bucket_name,
                "region": AWS_REGION
            }

        except ClientError as e:
            logger.error(f"Failed to create vulnerable bucket: {e}")
            return {"success": False, "error": str(e)}

    def cleanup_resource(self, resource_id):
        """Clean up a specific resource"""
        if not resource_id.startswith(DEMO_BUCKET_PREFIX):
            return {"success": False, "error": "Safety violation: Cannot delete non-demo resources"}
            
        try:
            logger.info(f"Cleaning up resource: {resource_id}")
            
            # 1. Empty the bucket first (if any objects exist)
            try:
                objects = self.s3_client.list_objects_v2(Bucket=resource_id)
                if 'Contents' in objects:
                    for obj in objects['Contents']:
                        self.s3_client.delete_object(Bucket=resource_id, Key=obj['Key'])
            except ClientError:
                pass # Bucket might already be gone or empty
            
            # 2. Delete the bucket
            self.s3_client.delete_bucket(Bucket=resource_id)
            
            if resource_id in self.active_simulations:
                del self.active_simulations[resource_id]
                
            return {"success": True, "message": f"Resource {resource_id} deleted."}
            
        except ClientError as e:
            logger.error(f"Failed to cleanup resource {resource_id}: {e}")
            return {"success": False, "error": str(e)}

    def _schedule_cleanup(self, bucket_name, delay_seconds=900): # 15 minutes default
        """Schedule a background thread to delete the bucket after delay"""
        def cleanup_task():
            logger.info(f"Cleanup timer started for {bucket_name} ({delay_seconds}s)")
            time.sleep(delay_seconds)
            self.cleanup_resource(bucket_name)
            
        thread = threading.Thread(target=cleanup_task)
        thread.daemon = True
        thread.start()

# Singleton instance
simulation_service = SimulationService()
