import boto3
import requests
from BucketACLS import audit_bucket_security, audit_bucket_acl
from mongodb_client import store_finding_to_mongodb
import json
import os

s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Lambda handler for S3 bucket auditing triggered by EventBridge
    Handles both EventBridge events and direct invocations
    """
    try:
        # Initialize variables
        bucket_name = None
        region = None
        account_id = None
        
        # Check if event is from EventBridge
        if event.get('event_source') == 'eventbridge':
            # EventBridge event structure
            bucket_name = event.get('bucket_name')
            region = event.get('region', 'us-east-1')
            account_id = event.get('account_id')
            
            print(f"EventBridge triggered audit for bucket: {bucket_name}")
            print(f"Region: {region}, Account ID: {account_id}")
            
        else:
            # Direct invocation or other event sources
            bucket_name = event.get('bucket_name')
            region = event.get('region', os.environ.get('AWS_REGION', 'us-east-1'))
            
            # Try to get account ID from event or config
            account_id = event.get('account_id')
            if not account_id:
                try:
                    with open("../../../../setup_config.json", "r") as config_file:
                        config_data = json.load(config_file)
                        account_id = config_data.get('accountId')
                except Exception as e:
                    print(f"Could not load config: {e}")
                    # Fallback: get account ID from STS
                    sts = boto3.client('sts')
                    account_id = sts.get_caller_identity()['Account']
        
        # Validate required parameters
        if not bucket_name:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'bucket_name is required',
                    'event_received': event
                })
            }
        
        # Get bucket tags
        try:
            tagset = s3.get_bucket_tagging(Bucket=bucket_name)['TagSet']
        except Exception as e:
            print(f"No tags found for bucket {bucket_name}: {e}")
            tagset = [{"Key": "None", "Value": "None"}]
        
        # Perform security audit
        print(f"Starting security audit for bucket: {bucket_name}")
        audit_result = audit_bucket_acl(
            bucket_name=bucket_name,
            accountId=account_id,
            region=region,
            tagset=tagset
        )

        # Store findings in MongoDB if audit result contains findings
        mongodb_document_id = None
        if audit_result:
            print(f"Storing audit findings in MongoDB for bucket: {bucket_name}")
            try:
                mongodb_document_id = store_finding_to_mongodb(audit_result, bucket_name)
                if mongodb_document_id:
                    print(f"Successfully stored findings in MongoDB with ID: {mongodb_document_id}")
                else:
                    print("Failed to store findings in MongoDB")
            except Exception as e:
                print(f"Error storing findings in MongoDB: {str(e)}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully audited bucket: {bucket_name}',
                'bucket_name': bucket_name,
                'region': region,
                'account_id': account_id,
                'audit_result': audit_result,
                'mongodb_document_id': mongodb_document_id,
                'findings_stored': mongodb_document_id is not None
            })
        }
        
    except Exception as e:
        print(f"Error in lambda_handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'event_received': event
            })
        }

# For testing purposes - this will be removed in production
if __name__ == "__main__":
    # Test with hardcoded bucket name
    test_event = {
        'bucket_name': 'jayserverlesscspmfilesbucket',
        'region': 'ap-south-1'
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
