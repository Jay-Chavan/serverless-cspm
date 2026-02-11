
import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch

# Adjust path to import lambda code
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../real_time_monitoring/aws/lambda_deployment/s3_lambda')))

from S3_findings import lambda_handler

class TestS3PublicBucket(unittest.TestCase):
    @patch('S3_findings.s3')
    @patch('BucketACLS.boto3.client')
    def test_public_bucket_detection(self, mock_boto_client_factory, mock_s3_findings_s3):
        # 1. Setup Mock S3 for BucketACLS
        mock_s3_audit = MagicMock()
        mock_boto_client_factory.return_value = mock_s3_audit
        
        # 2. Setup Mock S3 for S3_findings (get_bucket_tagging)
        mock_s3_findings_s3.get_bucket_tagging.return_value = {'TagSet': []}
        
        # 3. Configure S3 Audit Mock to return "Risky" configuration
        # Public Access Block - simulates 'NoSuchPublicAccessBlockConfiguration' or just all False
        mock_s3_audit.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        }
        
        # Encryption - Basic AES256 (not KMS)
        mock_s3_audit.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}
        }
        
        from botocore.exceptions import ClientError
        
        # Mock other S3 calls to avoid errors
        # Use ClientError for "Not Found" scenarios
        
        # Ownership Controls
        error_ownership = {'Error': {'Code': 'OwnershipControlsNotFoundError', 'Message': 'The bucket ownership controls were not found'}}
        mock_s3_audit.get_bucket_ownership_controls.side_effect = ClientError(error_ownership, 'GetBucketOwnershipControls')
        
        mock_s3_audit.get_bucket_versioning.return_value = {'Status': 'Disabled'}
        
        # Policy
        error_policy = {'Error': {'Code': 'NoSuchBucketPolicy', 'Message': 'The bucket policy does not exist'}}
        mock_s3_audit.get_bucket_policy.side_effect = ClientError(error_policy, 'GetBucketPolicy')
        
        # Logging
        # Logging returns empty dict if disabled, usually doesn't raise unless bucket not found?
        # But code catches ClientError.
        # Let's just return empty 'LoggingEnabled' which means disabled.
        mock_s3_audit.get_bucket_logging.return_value = {} # No LoggingEnabled key
        
        mock_s3_audit.get_bucket_notification_configuration.return_value = {}

        mock_s3_audit.audit_kms_key_security.return_value = None # Secure Key

        # Real OPA Integration
        # Ensure OPA_SERVER_IP is correct (handled by opa_client.py default or env var)
        # os.environ['OPA_SERVER_IP'] = '13.127.112.150' 
        
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

        event_detail = {
                'eventSource': 's3.amazonaws.com', 
                'eventName': 'CreateBucket',
                'requestParameters': {'bucketName': 'test-public-bucket'},
                'awsRegion': 'ap-south-1',
                'userIdentity': {'accountId': '123456789012'}
        }
        
        event = {
            'Records': [
                {'body': json.dumps({'detail': event_detail})}
            ]
        }
                
        print("Running Test Case 1: Public Bucket Detection (REAL OPA & Real DB)...")
        result = lambda_handler(event, None)
                
        print("Result:", json.dumps(result, indent=2))
                
        # Assertions
        self.assertEqual(result['statusCode'], 200)
        self.assertIn('Successfully processed', result['body'])

        
if __name__ == '__main__':
    unittest.main()
