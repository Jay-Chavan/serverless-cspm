
import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../real_time_monitoring/aws/lambda_deployment/s3_lambda')))

from S3_findings import lambda_handler

class TestS3KMSBucket(unittest.TestCase):
    @patch('S3_findings.s3')
    @patch('BucketACLS.boto3.client')
    def test_kms_bucket_audit(self, mock_boto_client_factory, mock_s3_findings_s3):
        # 1. Setup Mock S3 for BucketACLS
        mock_s3_audit = MagicMock()
        mock_boto_client_factory.return_value = mock_s3_audit
        
        # 2. Setup Mock S3 for S3_findings
        mock_s3_findings_s3.get_bucket_tagging.return_value = {'TagSet': [{'Key': 'Confidentiality', 'Value': 'High'}]}
        
        # 3. Setup Audit Responses (S3 Config)
        mock_s3_audit.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}
        }
        
        mock_s3_audit.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': 'alias/my-key'}}]}
        }
        # Mock other calls
        # Return valid ownership for KMS case to go smooth
        mock_s3_audit.get_bucket_ownership_controls.return_value = {
            'OwnershipControls': {'Rules': [{'ObjectOwnership': 'BucketOwnerEnforced'}]}
        }
        
        mock_s3_audit.get_bucket_versioning.return_value = {'Status': 'Enabled'} 
        mock_s3_audit.get_bucket_logging.return_value = {'LoggingEnabled': {'TargetBucket': 'logs', 'TargetPrefix': 'prefix'}}
        mock_s3_audit.get_bucket_notification_configuration.return_value = {}
        from botocore.exceptions import ClientError
        mock_s3_audit.get_bucket_policy.side_effect = ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
        
        mock_s3_audit.audit_kms_key_security.return_value = None # Secure Key

        # Real OPA Integration
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

        # SQS Event Structure
        event_detail = {
                'eventSource': 's3.amazonaws.com', 
                'eventName': 'CreateBucket',
                'requestParameters': {'bucketName': 'test-kms-bucket'},
                'awsRegion': 'ap-south-1',
                'userIdentity': {'accountId': '123456789012'}
        }
        
        event = {
            'Records': [
                {'body': json.dumps({'detail': event_detail})}
            ]
        }
            
        print("Running Test Case 2: KMS Bucket Audit (REAL OPA & Real DB)...")
        result = lambda_handler(event, None)
        print("Result:", json.dumps(result, indent=2))
            
        self.assertEqual(result['statusCode'], 200)

if __name__ == '__main__':
    unittest.main()
