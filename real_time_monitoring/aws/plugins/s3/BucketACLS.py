import boto3
from botocore.exceptions import ClientError
from helper_functions.hashing import calculate_md5
import json
from datetime import datetime, timezone
from opa_client import send_opa_request, parse_opa_response
import sys
import os

# Import KMS API client for communicating with KMS Lambda
from kms_api_client import get_kms_client

# --- Configuration ---
OPERATION = "S3BucketSecurityAudit"

def normalize_severity(risk_level):
    """Maps OPA risk level to the AWS Security Hub Severity format."""
    mapping = {
        "Critical": {"Label": "CRITICAL", "Normalized": 90},
        "Medium": {"Label": "MEDIUM", "Normalized": 50},
        "Low": {"Label": "LOW", "Normalized": 30},
        "Informational": {"Label": "INFORMATIONAL", "Normalized": 10}
    }
    return mapping.get(risk_level, {"Label": "HIGH", "Normalized": 70})

def get_s3_bucket_security_config(bucket_name, s3_client):
    """
    Collects comprehensive S3 bucket security configuration.
    
    Args:
        bucket_name: Name of the S3 bucket
        s3_client: Boto3 S3 client
        
    Returns:
        Dictionary containing all security-related configurations
    """
    config = {
        "bucket_name": bucket_name,
        "encryption": None,
        "bucket_ownership": None,
        "acls_enabled": False,
        "public_access": None,
        "versioning": None,
        "mfa_delete": None,
        "bucket_policy": None,
        "logging": None,
        "notification": None
    }
    
    # 1. Get bucket encryption
    try:
        print("[DEBUG] Fetching bucket encryption...")
        encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        if rules:
            sse_algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
            kms_key_id = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
            if sse_algorithm == 'aws:kms' and kms_key_id:
                config["encryption"] = f"KMS-{kms_key_id}"
            elif sse_algorithm:
                config["encryption"] = sse_algorithm
        print(f"[DEBUG] >> Encryption: {config['encryption']}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
            print(f"[WARNING] Could not get encryption config: {e}")
        config["encryption"] = "none"
    
    # 2. Get bucket ownership controls
    try:
        print("[DEBUG] Fetching bucket ownership controls...")
        ownership_controls = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
        bucket_ownership = ownership_controls['OwnershipControls']['Rules'][0]['ObjectOwnership']
        config["bucket_ownership"] = bucket_ownership
        config["acls_enabled"] = bucket_ownership in ['BucketOwnerPreferred', 'ObjectWriter']
        print(f"[DEBUG] >> Ownership: {bucket_ownership}, ACLs enabled: {config['acls_enabled']}")
    except (ClientError, KeyError, IndexError) as e:
        print(f"[WARNING] Could not get ownership controls: {e}")
        config["bucket_ownership"] = "unknown"
    
    # 3. Get public access block
    try:
        print("[DEBUG] Fetching public access block...")
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
        pab_config = public_access_block.get('PublicAccessBlockConfiguration', {})
        if all([
            pab_config.get('BlockPublicAcls', False),
            pab_config.get('IgnorePublicAcls', False),
            pab_config.get('BlockPublicPolicy', False),
            pab_config.get('RestrictPublicBuckets', False)
        ]):
            config["public_access"] = "blocked"
        else:
            config["public_access"] = "enabled"
        print(f"[DEBUG] >> Public access: {config['public_access']}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
            print(f"[WARNING] Could not get public access block: {e}")
        config["public_access"] = "enabled"  # Default if no PAB
    
    # 4. Get versioning configuration
    try:
        print("[DEBUG] Fetching versioning configuration...")
        versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        versioning_status = versioning_response.get('Status', 'Disabled')
        mfa_delete = versioning_response.get('MfaDelete', 'Disabled')
        config["versioning"] = versioning_status.lower()
        config["mfa_delete"] = mfa_delete.lower()
        print(f"[DEBUG] >> Versioning: {config['versioning']}, MFA Delete: {config['mfa_delete']}")
    except ClientError as e:
        print(f"[WARNING] Could not get versioning config: {e}")
        config["versioning"] = "disabled"
        config["mfa_delete"] = "disabled"
    
    # 5. Get bucket policy
    try:
        print("[DEBUG] Fetching bucket policy...")
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = policy_response.get('Policy')
        if policy_document:
            # Parse and store the policy
            config["bucket_policy"] = json.loads(policy_document)
        print(f"[DEBUG] >> Bucket policy: {'present' if config['bucket_policy'] else 'none'}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
            print(f"[WARNING] Could not get bucket policy: {e}")
        config["bucket_policy"] = None
    
    # 6. Get logging configuration
    try:
        print("[DEBUG] Fetching logging configuration...")
        logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
        logging_config = logging_response.get('LoggingEnabled')
        if logging_config:
            config["logging"] = {
                "target_bucket": logging_config.get('TargetBucket'),
                "target_prefix": logging_config.get('TargetPrefix', '')
            }
        else:
            config["logging"] = "disabled"
        print(f"[DEBUG] >> Logging: {'enabled' if config['logging'] != 'disabled' else 'disabled'}")
    except ClientError as e:
        print(f"[WARNING] Could not get logging config: {e}")
        config["logging"] = "disabled"
    
    # 7. Get notification configuration
    try:
        print("[DEBUG] Fetching notification configuration...")
        notification_response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        has_notifications = any([
            notification_response.get('TopicConfigurations', []),
            notification_response.get('QueueConfigurations', []),
            notification_response.get('LambdaConfigurations', [])
        ])
        config["notification"] = "enabled" if has_notifications else "disabled"
        print(f"[DEBUG] >> Notifications: {config['notification']}")
    except ClientError as e:
        print(f"[WARNING] Could not get notification config: {e}")
        config["notification"] = "disabled"
    
    return config

def audit_bucket_security(bucket_name, account_id, region, tagset=None, s3_client=None):
    """
    Performs comprehensive S3 bucket security audit, queries OPA, and formats a Security Hub finding.
    
    Args:
        bucket_name: S3 bucket name
        account_id: AWS account ID
        region: AWS region
        tagset: Optional bucket tags
        s3_client: Optional boto3 S3 client
        
    Returns:
        Security Hub finding dictionary or None if no issues found
    """
    print("\n" + "="*50) # New entry separator
    print(f"[INFO] Starting comprehensive S3 security audit for bucket: '{bucket_name}' in region '{region}'")

    if s3_client is None:
        s3_client = boto3.client('s3', region_name=region)

    # --- 1. Collect comprehensive S3 security configuration ---
    print("[DEBUG] Step 1: Collecting comprehensive S3 security configuration...")
    try:
        s3_config = get_s3_bucket_security_config(bucket_name, s3_client)
        if s3_config is None:
            print(f"[ERROR] Could not collect S3 configuration for bucket '{bucket_name}'.")
            return None
            
        print(f"[DEBUG] >> Successfully collected S3 security configuration")
        print(f"[DEBUG] >> Configuration summary: {json.dumps(s3_config, indent=2, default=str)}")
    except Exception as e:
        print(f"[ERROR] !! FAILED at Step 1. Could not collect S3 security configuration for bucket '{bucket_name}'. Reason: {e}")
        return None

    # --- 1.5. Check KMS encryption and audit KMS key if present ---
    kms_finding_id = None
    kms_audit_result = None
    
    encryption_config = s3_config.get("encryption", {})
    if encryption_config and encryption_config.get("sse_algorithm") == "aws:kms":
        kms_key_id = encryption_config.get("kms_master_key_id")
        if kms_key_id:
            print(f"[DEBUG] Step 1.5: S3 bucket uses KMS encryption with key: {kms_key_id}")
            print(f"[DEBUG] >> Performing KMS security audit...")
            try:
                kms_client = get_kms_client()
                kms_audit_result = kms_client.audit_kms_key_security(kms_key_id, account_id, region)
                if kms_audit_result:
                    # Extract the finding ID from KMS audit result
                    kms_finding_id = kms_audit_result["Findings"][0]["UserDefinedFields"]["FindingId"]
                    print(f"[DEBUG] >> KMS audit completed. Finding ID: {kms_finding_id}")
                    # Update S3 encryption config to indicate insecure KMS key
                    s3_config["encryption"]["kms_security_status"] = "insecure kms key"
                    s3_config["encryption"]["linked_kms_finding_id"] = kms_finding_id
                else:
                    print(f"[DEBUG] >> KMS key is secure, no findings generated")
                    s3_config["encryption"]["kms_security_status"] = "secure kms key"
            except Exception as e:
                print(f"[WARNING] KMS audit failed for key {kms_key_id}: {e}")
                s3_config["encryption"]["kms_security_status"] = "kms audit failed"

    # --- 2. Query OPA with comprehensive configuration ---
    print("[DEBUG] Step 2: Querying OPA with comprehensive configuration...")
    
    # Determine which OPA endpoint to use based on encryption type
    use_kms_endpoint = False
    encryption_config = s3_config.get("encryption")
    if encryption_config and isinstance(encryption_config, str) and encryption_config.startswith("KMS-"):
        use_kms_endpoint = True
        print(f"[DEBUG] >> Using KMS audit endpoint for KMS encryption: {encryption_config}")
    else:
        print(f"[DEBUG] >> Using SSE audit endpoint for encryption: {encryption_config}")
    
    response_data = send_opa_request(s3_config, use_kms_endpoint)
    if response_data is None:
        print(f"[ERROR] !! FAILED at Step 2. OPA request failed for bucket '{bucket_name}'.")
        return None

    # --- 3. Parse the OPA result ---
    print("[DEBUG] Step 3: Parsing OPA response...")
    finding_details = parse_opa_response(response_data)
    if finding_details is None:
        print(f"[INFO] No findings for bucket '{bucket_name}'. It is compliant.")
        print("="*50 + "\n")
        # Return KMS finding if it exists, even if S3 is compliant
        return kms_audit_result
    
    risk = finding_details["risk_level"]
    reason = finding_details["reason"]

    # --- 4. Generate comprehensive finding ---
    print("[DEBUG] Step 4: Generating comprehensive security finding...")

    finding_id_source = f"{account_id}{region}{bucket_name}{OPERATION}"
    finding_id = calculate_md5(finding_id_source)
    finding_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    
    # Create detailed description with security configuration summary
    security_summary = []
    if not s3_config.get("encryption"):
        security_summary.append("No encryption")
    elif s3_config.get("encryption", {}).get("sse_algorithm") == "AES256":
        security_summary.append("SSE-S3 encryption only")
    elif s3_config.get("encryption", {}).get("kms_security_status") == "insecure kms key":
        security_summary.append("Insecure KMS key encryption")
    
    if s3_config.get("public_access_block", {}).get("block_public_acls") == False:
        security_summary.append("Public ACLs allowed")
    
    if s3_config.get("versioning", {}).get("status") != "Enabled":
        security_summary.append("Versioning disabled")
    
    if not s3_config.get("logging"):
        security_summary.append("Access logging disabled")
    
    description = f"S3 bucket '{bucket_name}' has security configuration issues. "
    if security_summary:
        description += f"Issues found: {', '.join(security_summary)}. "
    description += f"Policy evaluation reason: {reason}"
    
    # Prepare user defined fields
    user_defined_fields = {
        "S3Configuration": json.dumps(s3_config, default=str),
        "FindingId": finding_id
    }
    
    # Add KMS finding information if present
    if kms_finding_id:
        user_defined_fields["LinkedKMSFindingId"] = kms_finding_id
        user_defined_fields["KMSSecurityStatus"] = s3_config.get("encryption", {}).get("kms_security_status")
    
    finding = {
        "Findings": [
            {
                "SchemaVersion": "2018-10-08",
                "Id": f"arn:aws:s3:::{bucket_name}/{OPERATION}",
                "ProductArn": f"arn:aws:securityhub:{region}::{account_id}:product/{account_id}/default",
                "GeneratorId": "cspm-s3-security-audit",
                "AwsAccountId": account_id,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "CreatedAt": finding_timestamp,
                "UpdatedAt": finding_timestamp,
                "Severity": normalize_severity(risk),
                "Title": "S3 Bucket Security Configuration Issues Detected",
                "Description": description,
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": f"arn:aws:s3:::{bucket_name}",
                        "Partition": "aws",
                        "Region": region,
                        "Details": {
                            "AwsS3Bucket": {
                                "Name": bucket_name,
                                "OwnerId": s3_config.get("ownership", {}).get("owner_id"),
                                "OwnerName": s3_config.get("ownership", {}).get("owner_display_name"),
                                "CreationDate": s3_config.get("creation_date"),
                                "ServerSideEncryptionConfiguration": {
                                    "Rules": [
                                        {
                                            "ApplyServerSideEncryptionByDefault": {
                                                "SSEAlgorithm": s3_config.get("encryption", {}).get("sse_algorithm"),
                                                "KMSMasterKeyID": s3_config.get("encryption", {}).get("kms_master_key_id"),
                                                "KMSSecurityStatus": s3_config.get("encryption", {}).get("kms_security_status")
                                            }
                                        }
                                    ] if s3_config.get("encryption") else []
                                },
                                "PublicAccessBlockConfiguration": s3_config.get("public_access_block", {}),
                                "BucketVersioningConfiguration": {
                                    "Status": s3_config.get("versioning", {}).get("status"),
                                    "MfaDelete": s3_config.get("versioning", {}).get("mfa_delete")
                                },
                                "BucketLoggingConfiguration": s3_config.get("logging", {}),
                                "BucketNotificationConfiguration": s3_config.get("notification", {})
                            }
                        }
                    }
                ],
                "RecordState": "ACTIVE",
                "WorkflowState": "NEW",
                "Compliance": {
                    "Status": "FAILED",
                    "SecurityControlId": "S3.1",
                    "AssociatedStandards": [
                        {
                            "StandardsId": "aws-foundational-security-standard"
                        }
                    ]
                },
                "UserDefinedFields": user_defined_fields
            }
        ]
    }
    
    print(f"[INFO] Successfully generated comprehensive security finding for bucket '{bucket_name}'.")
    print("[DEBUG] Final Finding Object:")
    print(json.dumps(finding, indent=2, default=str)) # Pretty print the final JSON
    print("="*50 + "\n")
    return finding

# Backward compatibility alias
def audit_bucket_acl(bucket_name, accountId, region, tagset, s3_client=None):
    """
    Legacy function name for backward compatibility.
    Calls the new comprehensive audit function.
    """
    return audit_bucket_security(bucket_name, accountId, region, tagset, s3_client)