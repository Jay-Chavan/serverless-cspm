import boto3
import json

def invoke_lambda():
    client = boto3.client('lambda', region_name='ap-south-1')
    
    # Simulate a DeleteBucket event from EventBridge -> SQS -> Lambda
    # The Lambda expects an SQS event with a body containing the EventBridge detail
    
    payload = {
        "Records": [
            {
                "body": json.dumps({
                    "detail": {
                        "eventSource": "s3.amazonaws.com",
                        "eventName": "DeleteBucket",
                        "awsRegion": "ap-south-1",
                        "userIdentity": {
                            "accountId": "554739427981"
                        },
                        "requestParameters": {
                            "bucketName": "test-bucket-for-deletion-verification"
                        }
                    }
                })
            }
        ]
    }
    
    print("Invoking Lambda 'cspm-s3-auditor' with simulated DeleteBucket event...")
    
    try:
        response = client.invoke(
            FunctionName='cspm-s3-auditor',
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        response_payload = response['Payload'].read().decode('utf-8')
        print(f"Response Code: {response['StatusCode']}")
        print(f"Response Payload: {response_payload}")
        
    except Exception as e:
        print(f"Error invoking Lambda: {e}")

if __name__ == "__main__":
    invoke_lambda()
