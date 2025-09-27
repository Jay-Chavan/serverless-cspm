# S3 Comprehensive Security Audit

This module provides comprehensive S3 bucket security auditing capabilities with integrated KMS key security evaluation, collecting all security-related properties and evaluating them against OPA (Open Policy Agent) policies.

## Features

The audit system now checks the following S3 security properties with KMS integration:

### 🔐 Encryption
- **Server-Side Encryption (SSE-S3)**: `AES256`
- **Server-Side Encryption with KMS**: `KMS-{key-id}`
- **No Encryption**: `none`

### 🏠 Ownership & Access Control
- **Bucket Ownership Controls**: `BucketOwnerEnforced`, `BucketOwnerPreferred`, `ObjectWriter`
- **ACLs Status**: Enabled/Disabled based on ownership settings
- **Public Access Block**: All four settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)

### 📝 Versioning & Protection
- **Versioning Status**: `enabled`, `suspended`, `disabled`
- **MFA Delete**: `enabled`, `disabled`

### 📋 Policies & Configuration
- **Bucket Policy**: Complete policy document (JSON)
- **Access Logging**: Target bucket and prefix configuration
- **Event Notifications**: SNS, SQS, Lambda configurations

## Files

### Core Files
- **`BucketACLS.py`**: Main audit module with comprehensive security checks
- **`opa_client.py`**: Separated OPA request handling logic
- **`S3_findings.py`**: Example usage and integration
- **`test_comprehensive_audit.py`**: Test script demonstrating functionality

### Helper Files
- **`helper_functions/hashing.py`**: MD5 hashing utilities
- **`helper_functions/__init__.py`**: Package initialization

## Usage

### Basic Usage with KMS Integration

```python
from BucketACLS import audit_bucket_security
import boto3
import json

# Initialize S3 client
s3_client = boto3.client('s3')

# Sample bucket tags
tagset = [
    {"Key": "Environment", "Value": "Production"},
    {"Key": "Owner", "Value": "SecurityTeam"}
]

# Run comprehensive audit (includes automatic KMS audit)
finding = audit_bucket_security(
    bucket_name="your-bucket-name",
    accountId="123456789012",
    region="us-east-1",
    tagset=tagset,
    s3_client=s3_client  # Optional
)

if finding:
    print("Security issues found!")
    
    # Check if this includes KMS findings
    user_fields = finding.get("UserDefinedFields", {})
    
    if "LinkedKMSFindingId" in user_fields:
        print(f"S3 bucket has linked KMS security issues")
        print(f"KMS Finding ID: {user_fields['LinkedKMSFindingId']}")
        print(f"KMS Security Status: {user_fields['KMSSecurityStatus']}")
    
    # Process the Security Hub finding
else:
    print("Bucket is compliant")
```

### KMS Integration Workflow

When an S3 bucket uses KMS encryption, the audit automatically:

1. **Detects KMS Usage**: Identifies the KMS key ID from bucket encryption configuration
2. **Triggers KMS Audit**: Performs comprehensive KMS key security evaluation
3. **Updates S3 Config**: Adds KMS security status to S3 configuration:
   ```json
   {
     "encryption": {
       "sse_algorithm": "aws:kms",
       "kms_master_key_id": "key-id",
       "kms_security_status": "insecure kms key",
       "linked_kms_finding_id": "kms-finding-id"
     }
   }
   ```
4. **Links Findings**: Includes KMS finding ID in S3 finding's UserDefinedFields
5. **OPA Evaluation**: Sends updated configuration (including KMS status) to OPA

### Configuration Collection Only

```python
from BucketACLS import get_s3_bucket_security_config
import boto3
import json

s3_client = boto3.client('s3')
config = get_s3_bucket_security_config("your-bucket-name", s3_client)

print("Complete Security Configuration:")
print(json.dumps(config, indent=2, default=str))
```

### Legacy Compatibility

The original `audit_bucket_acl()` function is still available and now calls the comprehensive audit:

```python
from BucketACLS import audit_bucket_acl

# This now performs comprehensive audit
finding = audit_bucket_acl(
    bucket_name="your-bucket-name",
    accountId="123456789012",
    region="us-east-1",
    tagset=tagset
)
```

## Input JSON Structure

The comprehensive audit creates the following input structure for OPA:

```json
{
  "input": {
    "resource_type": "s3",
    "bucket_config": {
      "bucket_name": "example-bucket",
      "encryption": "KMS-arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
      "bucket_ownership": "BucketOwnerEnforced",
      "acls_enabled": false,
      "public_access": "blocked",
      "versioning": "enabled",
      "mfa_delete": "disabled",
      "bucket_policy": {
        "Version": "2012-10-17",
        "Statement": [...]
      },
      "logging": {
        "target_bucket": "access-logs-bucket",
        "target_prefix": "access-logs/"
      },
      "notification": "enabled",
      "tagset": [
        {"Key": "Environment", "Value": "Production"}
      ]
    }
  }
}
```

## Security Hub Finding

The audit generates comprehensive Security Hub findings with:

- **Detailed Resource Information**: Complete S3 bucket configuration in AWS Security Hub format
- **Compliance Status**: Mapped to AWS Foundational Security Standard
- **User-Defined Fields**: Raw configuration data for further analysis
- **Severity Mapping**: Critical, High, Medium, Low, Informational

## Configuration

### OPA Server
Update the OPA URL in `opa_client.py`:

```python
OPA_URL = "http://your-opa-server:8181/v1/data/aws/s3_creation/deny"
```

### AWS Credentials

Ensure your AWS credentials have the necessary S3 and KMS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketEncryption",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketPolicy",
        "s3:GetBucketLogging",
        "s3:GetBucketNotification",
        "s3:GetBucketTagging",
        "s3:ListBucket"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListGrants",
        "kms:ListResourceTags"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.*.amazonaws.com"
        }
      }
    }
  ]
}
```

## Testing

Run the test script to verify functionality:

```bash
python test_comprehensive_audit.py
```

Update the bucket name, account ID, and region in the script before running.

## Migration from Legacy Version

1. **No Code Changes Required**: Existing calls to `audit_bucket_acl()` will automatically use the new comprehensive audit
2. **Enhanced Data**: The same function now collects much more security data
3. **Improved Findings**: Security Hub findings now include detailed configuration information
4. **OPA Integration**: Separated into `opa_client.py` for better maintainability

## Error Handling

The audit system gracefully handles:
- Missing bucket configurations (uses safe defaults)
- AWS API errors (logs warnings, continues with available data)
- OPA server connectivity issues
- Malformed responses

All errors are logged with appropriate debug information for troubleshooting.