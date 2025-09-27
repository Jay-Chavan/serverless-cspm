import boto3
import requests
from BucketACLS import audit_bucket_security, audit_bucket_acl
from mongodb_client import store_finding_to_mongodb
import json
import os

s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Lambda handler for S3 bucket auditing triggered by SQS messages from EventBridge
    Handles SQS events containing CloudTrail data and direct invocations
    """
    try:
        # Initialize variables
        bucket_name = None
        region = None
        account_id = None
        
        # Check if event is from SQS (contains Records)
        if 'Records' in event:
            print("Processing SQS event from EventBridge")
            
            # Process each SQS record (typically one record per invocation)
            for record in event['Records']:
                # Parse the SQS message body which contains the CloudTrail event
                message_body = json.loads(record['body'])
                
                # Extract CloudTrail event details
                if 'detail' in message_body:
                    detail = message_body['detail']
                    
                    # Extract bucket name from CloudTrail event
                    if 'requestParameters' in detail and 'bucketName' in detail['requestParameters']:
                        bucket_name = detail['requestParameters']['bucketName']
                    
                    # Extract region and account ID
                    region = detail.get('awsRegion', 'us-east-1')
                    account_id = detail.get('userIdentity', {}).get('accountId')
                    
                    print(f"SQS/EventBridge triggered audit for bucket: {bucket_name}")
                    print(f"Region: {region}, Account ID: {account_id}")
                    print(f"CloudTrail event: {detail.get('eventName')}")
                    
                    # Process the bucket audit for this record
                    process_bucket_audit(bucket_name, region, account_id)
                    
        elif event.get('event_source') == 'eventbridge':
            # Legacy EventBridge event structure (for backward compatibility)
            bucket_name = event.get('bucket_name')
            region = event.get('region', 'us-east-1')
            account_id = event.get('account_id')
            
            print(f"Direct EventBridge triggered audit for bucket: {bucket_name}")
            print(f"Region: {region}, Account ID: {account_id}")
            
            # Process the bucket audit
            return process_bucket_audit(bucket_name, region, account_id)
            
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
            
            print(f"Direct invocation audit for bucket: {bucket_name}")
            return process_bucket_audit(bucket_name, region, account_id)
        
        # For SQS events, return success after processing all records
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed SQS records',
                'records_processed': len(event.get('Records', []))
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

def process_bucket_audit(bucket_name, region, account_id):
    """
    Process the S3 bucket audit for a given bucket
    """
    try:
        # Validate required parameters
        if not bucket_name:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'bucket_name is required',
                    'bucket_name': bucket_name
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
        print(f"Error in process_bucket_audit: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'bucket_name': bucket_name
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
