# KMS Security Audit Module

This module provides comprehensive security auditing for AWS KMS (Key Management Service) keys, with seamless integration into the S3 security audit workflow.

## Features

### Comprehensive KMS Security Checks
- **Key Metadata Analysis**: State, usage, specification, origin, and management details
- **Key Policy Evaluation**: Retrieval and analysis of key policies
- **Key Rotation Status**: Automatic key rotation configuration
- **Key Aliases**: Associated aliases and naming conventions
- **Key Grants**: Active grants and their permissions
- **Key Tags**: Resource tagging compliance
- **Multi-Region Keys**: Replica key analysis for multi-region setups

### OPA Integration
- Sends comprehensive KMS configuration to OPA endpoint: `v1/data/aws/kms_key/deny`
- Receives policy evaluation results with risk levels and reasons
- Supports custom OPA policies for KMS security evaluation

### Security Hub Integration
- Generates AWS Security Hub compatible findings
- Includes detailed KMS key configuration in finding resources
- Provides comprehensive compliance status and security control mapping

### S3 Integration
- Automatically triggered when S3 buckets use KMS encryption
- Links KMS findings to S3 findings for comprehensive security posture
- Updates S3 encryption status based on KMS security evaluation

## File Structure

```
kms/
├── __init__.py                 # Module initialization
├── KMSAudit.py                # Main KMS audit functionality
├── kms_opa_client.py          # OPA communication client
└── README.md                  # This documentation
```

## Usage Examples

### Basic KMS Audit

```python
from KMSAudit import audit_kms_key_security

# Audit a specific KMS key
result = audit_kms_key_security(
    key_id="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    account_id="123456789012",
    region="us-east-1"
)

if result:
    print("KMS security issues found:")
    print(json.dumps(result, indent=2, default=str))
else:
    print("KMS key is compliant")
```

### Configuration Collection Only

```python
from KMSAudit import get_kms_key_security_config
import boto3

kms_client = boto3.client('kms', region_name='us-east-1')
config = get_kms_key_security_config(
    key_id="12345678-1234-1234-1234-123456789012",
    kms_client=kms_client
)

print("KMS Configuration:")
print(json.dumps(config, indent=2, default=str))
```

### Integration with S3 Audit

The KMS audit is automatically triggered when S3 buckets use KMS encryption:

```python
from s3.BucketACLS import audit_bucket_security

# This will automatically audit KMS keys if the bucket uses KMS encryption
result = audit_bucket_security(
    bucket_name="my-encrypted-bucket",
    account_id="123456789012",
    region="us-east-1"
)

# Check for linked KMS findings
if result and "LinkedKMSFindingId" in result["Findings"][0]["UserDefinedFields"]:
    print("S3 bucket has linked KMS security issues")
    print(f"KMS Finding ID: {result['Findings'][0]['UserDefinedFields']['LinkedKMSFindingId']}")
```

## Input JSON Structure

The module sends the following JSON structure to OPA:

```json
{
  "key_id": "12345678-1234-1234-1234-123456789012",
  "key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
  "key_state": "Enabled",
  "key_usage": "ENCRYPT_DECRYPT",
  "key_spec": "SYMMETRIC_DEFAULT",
  "origin": "AWS_KMS",
  "key_manager": "CUSTOMER",
  "deletion_date": null,
  "key_policy": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "key_rotation_enabled": true,
  "aliases": ["alias/my-key"],
  "grants": [
    {
      "grant_id": "grant-123",
      "grantee_principal": "arn:aws:iam::123456789012:role/MyRole",
      "operations": ["Decrypt", "GenerateDataKey"],
      "constraints": {}
    }
  ],
  "tags": [
    {
      "TagKey": "Environment",
      "TagValue": "Production"
    }
  ],
  "multi_region": false,
  "replica_keys": []
}
```

## Security Hub Finding Structure

Generated findings include:

- **Comprehensive Resource Details**: Key metadata, rotation status, grants, aliases
- **Security Configuration**: Policy analysis, encryption capabilities, multi-region setup
- **Compliance Mapping**: AWS Foundational Security Standard controls
- **User Defined Fields**: Complete KMS configuration and finding correlation

## Configuration

### OPA Server Setup

1. Ensure OPA server is running and accessible
2. Configure the OPA URL in `kms_opa_client.py`:
   ```python
   KMS_OPA_URL = "http://your-opa-server:8181/v1/data/aws/kms_key/deny"
   ```

### AWS Credentials

Ensure your AWS credentials have the following KMS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
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
      "Resource": "*"
    }
  ]
}
```

## Testing

Use the test script to validate functionality:

```bash
cd /path/to/s3/
python test_integrated_audit.py
```

The test script demonstrates:
- Integrated S3-KMS audit workflow
- KMS-only audit functionality
- Finding correlation and linking
- Security Hub finding generation

## Integration with S3 Module

### Automatic Triggering

When an S3 bucket uses KMS encryption, the S3 audit automatically:

1. **Detects KMS Usage**: Identifies KMS key ID from S3 encryption configuration
2. **Triggers KMS Audit**: Calls `audit_kms_key_security()` for the detected key
3. **Updates S3 Config**: Adds KMS security status to S3 configuration
4. **Links Findings**: Includes KMS finding ID in S3 finding's UserDefinedFields

### S3 Configuration Updates

When KMS issues are found, the S3 configuration is updated:

```json
{
  "encryption": {
    "sse_algorithm": "aws:kms",
    "kms_master_key_id": "12345678-1234-1234-1234-123456789012",
    "kms_security_status": "insecure kms key",
    "linked_kms_finding_id": "abc123def456"
  }
}
```

### Finding Correlation

S3 findings include KMS correlation data:

```json
{
  "UserDefinedFields": {
    "S3Configuration": "{...}",
    "FindingId": "s3-finding-id",
    "LinkedKMSFindingId": "kms-finding-id",
    "KMSSecurityStatus": "insecure kms key"
  }
}
```

## Error Handling

The module includes comprehensive error handling:

- **AWS API Errors**: Graceful handling of permission and access issues
- **OPA Communication**: Retry logic and timeout handling
- **Configuration Issues**: Validation and fallback mechanisms
- **Integration Failures**: Isolated error handling to prevent S3 audit failures

## Best Practices

1. **Regular Audits**: Schedule regular KMS key audits
2. **Policy Updates**: Keep OPA policies updated with latest security requirements
3. **Monitoring**: Monitor OPA server availability and performance
4. **Permissions**: Use least-privilege IAM policies for KMS access
5. **Logging**: Enable detailed logging for audit trail and debugging

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure IAM permissions for KMS operations
2. **OPA Unreachable**: Verify OPA server URL and network connectivity
3. **Key Not Found**: Verify KMS key ID format and existence
4. **Integration Failures**: Check S3 module configuration and imports

### Debug Mode

Enable debug logging by setting environment variable:
```bash
export AWS_CSPM_DEBUG=true
```

This provides detailed logging of:
- KMS API calls and responses
- OPA communication details
- Configuration collection steps
- Finding generation process