# CSPM Lambda Deployment Guide

This guide covers the deployment of separate KMS and S3 Lambda functions with API communication.

## Architecture Overview

The new architecture separates KMS and S3 auditing into independent Lambda functions:

- **KMS Lambda**: Standalone function that provides KMS auditing services via API endpoints
- **S3 Lambda**: Function that audits S3 buckets and calls KMS Lambda for KMS key validation
- **API Gateway**: Provides HTTP endpoints for communication between Lambda functions

## Directory Structure

```
lambda_deployment/
├── kms_lambda/                 # KMS Lambda source code
│   ├── lambda_handler.py       # Main handler for KMS Lambda
│   ├── KMSAudit.py            # KMS audit logic
│   ├── kms_opa_client.py      # OPA client for KMS policies
│   ├── requirements.txt       # Dependencies
│   └── helper_functions/      # Helper utilities
├── s3_lambda/                 # S3 Lambda source code
│   ├── lambda_handler.py      # Main handler for S3 Lambda
│   ├── BucketACLS.py         # S3 audit logic
│   ├── kms_api_client.py     # Client for calling KMS Lambda
│   ├── opa_client.py         # OPA client for S3 policies
│   ├── requirements.txt      # Dependencies
│   └── helper_functions/     # Helper utilities
├── deploy_kms_lambda.py      # KMS Lambda deployment script
├── deploy_s3_lambda.py       # S3 Lambda deployment script
├── api_gateway_setup.py      # API Gateway setup script
└── README.md                 # This file
```

## Deployment Steps

### 1. Prepare Deployment Packages

Create deployment packages for both Lambda functions:

```powershell
# Navigate to the lambda_deployment directory
cd c:\Users\Rahul\Cloud&Security\CSPM\real_time_monitoring\aws\lambda_deployment

# Create KMS Lambda deployment package
python deploy_kms_lambda.py

# Create S3 Lambda deployment package
python deploy_s3_lambda.py
```

This will create:
- `kms_lambda.zip` - KMS Lambda deployment package
- `s3_lambda.zip` - S3 Lambda deployment package

### 2. Deploy Infrastructure with Terraform

Navigate to the terraform directory and deploy:

```powershell
cd c:\Users\Rahul\Cloud&Security\CSPM\real_time_monitoring\aws\terraform

# Initialize Terraform (if not already done)
terraform init

# Plan the deployment
terraform plan

# Apply the deployment
terraform apply
```

### 3. Verify Deployment

After deployment, verify the setup:

```powershell
# Check Terraform outputs
terraform output

# Test KMS Lambda health check
# Use the kms_api_gateway_url from terraform output
curl -X POST https://your-api-gateway-url/v1/health -H "Content-Type: application/json" -d "{}"
```

## Environment Variables

### KMS Lambda Environment Variables

- `OPA_SERVER_IP`: IP address of the OPA server
- `LOG_LEVEL`: Logging level (INFO, DEBUG, WARNING, ERROR)

### S3 Lambda Environment Variables

- `OPA_SERVER_IP`: IP address of the OPA server
- `KMS_LAMBDA_FUNCTION_NAME`: Name of the KMS Lambda function
- `KMS_API_GATEWAY_URL`: URL of the KMS API Gateway
- `LOG_LEVEL`: Logging level (INFO, DEBUG, WARNING, ERROR)

## API Endpoints

### KMS Lambda API Endpoints

The KMS Lambda provides the following API endpoints via API Gateway:

#### Health Check
- **Endpoint**: `POST /health`
- **Purpose**: Check if the KMS Lambda service is healthy
- **Request Body**: `{}`
- **Response**: Health status information

#### Audit KMS Key
- **Endpoint**: `POST /audit-key`
- **Purpose**: Audit a single KMS key for security issues
- **Request Body**:
  ```json
  {
    "action": "audit_key",
    "key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "account_id": "123456789012",
    "region": "us-east-1",
    "additional_params": {}
  }
  ```

#### Get Key Information
- **Endpoint**: `POST /key-info`
- **Purpose**: Get basic information about a KMS key
- **Request Body**:
  ```json
  {
    "action": "get_key_info",
    "key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "region": "us-east-1"
  }
  ```

## Communication Flow

1. **S3 Lambda** receives an event (API Gateway, S3, SQS, etc.)
2. **S3 Lambda** audits S3 bucket configuration
3. If S3 bucket uses KMS encryption, **S3 Lambda** calls **KMS Lambda** via API Gateway
4. **KMS Lambda** audits the KMS key and returns results
5. **S3 Lambda** combines S3 and KMS audit results
6. **S3 Lambda** sends findings to Security Hub and stores in MongoDB

## Troubleshooting

### Common Issues

1. **Lambda Function Not Found**
   - Ensure the Lambda functions are deployed correctly
   - Check the function names in environment variables

2. **API Gateway Timeout**
   - Check if the KMS Lambda is responding
   - Verify API Gateway configuration
   - Check CloudWatch logs for errors

3. **Permission Errors**
   - Verify IAM roles have correct permissions
   - Check Lambda execution roles
   - Ensure API Gateway has permission to invoke Lambda

### Debugging

1. **Check CloudWatch Logs**
   ```
   /aws/lambda/cspm-kms-auditor
   /aws/lambda/cspm-s3-auditor
   ```

2. **Test Individual Components**
   - Test KMS Lambda directly via AWS Console
   - Test API Gateway endpoints
   - Verify S3 Lambda can reach KMS API

3. **Monitor Performance**
   - Check Lambda execution duration
   - Monitor API Gateway latency
   - Review error rates in CloudWatch

## Security Considerations

1. **API Gateway Security**
   - Consider adding API keys or authentication
   - Implement rate limiting
   - Use VPC endpoints for internal communication

2. **Lambda Security**
   - Follow principle of least privilege for IAM roles
   - Enable VPC configuration if needed
   - Use environment variables for sensitive configuration

3. **Network Security**
   - Consider using VPC for Lambda functions
   - Implement security groups and NACLs
   - Use private subnets for enhanced security

## Performance Optimization

1. **Lambda Configuration**
   - Adjust memory allocation based on workload
   - Set appropriate timeout values
   - Use provisioned concurrency for consistent performance

2. **API Gateway**
   - Enable caching for frequently accessed endpoints
   - Configure throttling limits
   - Use regional endpoints for better performance

3. **Monitoring**
   - Set up CloudWatch alarms for errors and latency
   - Monitor Lambda cold starts
   - Track API Gateway metrics

## Maintenance

1. **Regular Updates**
   - Update Lambda runtime versions
   - Keep dependencies up to date
   - Review and update IAM policies

2. **Monitoring**
   - Set up alerts for failures
   - Monitor costs and usage
   - Review logs regularly

3. **Backup and Recovery**
   - Version control for Lambda code
   - Backup Terraform state
   - Document recovery procedures