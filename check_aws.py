
import boto3
import sys

try:
    s3 = boto3.client('s3', region_name='ap-south-1')
    buckets = s3.list_buckets()
    print("Successfully listed buckets. Count:", len(buckets['Buckets']))
except Exception as e:
    print("Failed to list buckets:", e)
    sys.exit(1)
