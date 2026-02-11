
import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../real_time_monitoring/aws/lambda_deployment/s3_lambda')))

from S3_findings import lambda_handler

class TestS3DeleteBucket(unittest.TestCase):
    def test_delete_bucket(self):
        # Load environment variables for MongoDB connection
        env_path = r'd:\Projects\CSPM\serverless-cspm\csmp-findings-dashboard\backend\.env'
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value
        except Exception as e:
            print(f"Warning: Could not load .env file: {e}")

        event = {
            'detail': {
                'eventSource': 's3.amazonaws.com', 
                'eventName': 'DeleteBucket', # Critical for triggering delete logic
                'requestParameters': {'bucketName': 'test-public-bucket'},
                'awsRegion': 'ap-south-1',
                'userIdentity': {'accountId': '123456789012'}
            }
        }
        
        # Mock Records structure for SQS event
        sqs_event = {
            'Records': [
                {'body': json.dumps({'detail': event['detail']})}
            ]
        }
        
        print("Running Test Case 3: Delete Bucket Event (Real DB - Cleanup test-public-bucket)...")
        # Note: calling lambda_handler with SQS event structure
        result = lambda_handler(sqs_event, None)
        print("Result:", json.dumps(result, indent=2))
        
        # We can't verify mock call anymore. We verify status code.
        self.assertEqual(result['statusCode'], 200)
        
if __name__ == '__main__':
    unittest.main()
