import boto3
from botocore.exceptions import ClientError
import json
from datetime import datetime, timezone
from kms_opa_client import send_kms_opa_request, parse_kms_opa_response
import sys
import os

# Add the parent directory to the path to import from s3 helper functions
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 's3', 'helper_functions'))
from hashing import calculate_md5

# --- Configuration ---
OPERATION = "KMSKeySecurityAudit"

def normalize_severity(risk_level):
    """Maps OPA risk level to the AWS Security Hub Severity format."""
    mapping = {
        "Critical": {"Label": "CRITICAL", "Normalized": 90},
        "Medium": {"Label": "MEDIUM", "Normalized": 50},
        "Low": {"Label": "LOW", "Normalized": 30},
        "Informational": {"Label": "INFORMATIONAL", "Normalized": 10}
    }
    return mapping.get(risk_level, {"Label": "HIGH", "Normalized": 70})

def get_kms_key_security_config(key_id, kms_client):
    """
    Collects comprehensive KMS key security configuration.
    
    Args:
        key_id: KMS key ID or ARN
        kms_client: Boto3 KMS client
        
    Returns:
        Dictionary containing all security-related configurations
    """
    config = {
        "key_id": key_id,
        "key_arn": None,
        "key_state": None,
        "key_usage": None,
        "key_spec": None,
        "origin": None,
        "key_manager": None,
        "deletion_date": None,
        "key_policy": None,
        "key_rotation_enabled": False,
        "aliases": [],
        "grants": [],
        "tags": [],
        "multi_region": False,
        "replica_keys": []
    }
    
    # 1. Get key metadata
    try:
        print("[DEBUG] Fetching KMS key metadata...")
        key_metadata = kms_client.describe_key(KeyId=key_id)
        key_info = key_metadata['KeyMetadata']
        
        config["key_arn"] = key_info.get('Arn')
        config["key_state"] = key_info.get('KeyState')
        config["key_usage"] = key_info.get('KeyUsage')
        config["key_spec"] = key_info.get('KeySpec')
        config["origin"] = key_info.get('Origin')
        config["key_manager"] = key_info.get('KeyManager')
        config["deletion_date"] = key_info.get('DeletionDate')
        config["multi_region"] = key_info.get('MultiRegion', False)
        
        print(f"[DEBUG] >> Key State: {config['key_state']}")
        print(f"[DEBUG] >> Key Manager: {config['key_manager']}")
        print(f"[DEBUG] >> Key Usage: {config['key_usage']}")
        
    except ClientError as e:
        print(f"[WARNING] Could not get key metadata: {e}")
        return None
    
    # 2. Get key policy
    try:
        print("[DEBUG] Fetching KMS key policy...")
        policy_response = kms_client.get_key_policy(
            KeyId=key_id,
            PolicyName='default'
        )
        policy_document = policy_response.get('Policy')
        if policy_document:
            config["key_policy"] = json.loads(policy_document)
        print(f"[DEBUG] >> Key policy: {'present' if config['key_policy'] else 'none'}")
    except ClientError as e:
        print(f"[WARNING] Could not get key policy: {e}")
        config["key_policy"] = None
    
    # 3. Get key rotation status
    try:
        print("[DEBUG] Fetching KMS key rotation status...")
        rotation_response = kms_client.get_key_rotation_status(KeyId=key_id)
        config["key_rotation_enabled"] = rotation_response.get('KeyRotationEnabled', False)
        print(f"[DEBUG] >> Key rotation enabled: {config['key_rotation_enabled']}")
    except ClientError as e:
        print(f"[WARNING] Could not get key rotation status: {e}")
        config["key_rotation_enabled"] = False
    
    # 4. Get key aliases
    try:
        print("[DEBUG] Fetching KMS key aliases...")
        aliases_response = kms_client.list_aliases()
        key_aliases = []
        for alias in aliases_response.get('Aliases', []):
            if alias.get('TargetKeyId') == key_id or alias.get('TargetKeyId') == config.get('key_arn'):
                key_aliases.append(alias.get('AliasName'))
        config["aliases"] = key_aliases
        print(f"[DEBUG] >> Aliases: {config['aliases']}")
    except ClientError as e:
        print(f"[WARNING] Could not get key aliases: {e}")
        config["aliases"] = []
    
    # 5. Get key grants
    try:
        print("[DEBUG] Fetching KMS key grants...")
        grants_response = kms_client.list_grants(KeyId=key_id)
        grants = grants_response.get('Grants', [])
        config["grants"] = [
            {
                "grant_id": grant.get('GrantId'),
                "grantee_principal": grant.get('GranteePrincipal'),
                "operations": grant.get('Operations', []),
                "constraints": grant.get('Constraints', {})
            }
            for grant in grants
        ]
        print(f"[DEBUG] >> Number of grants: {len(config['grants'])}")
    except ClientError as e:
        print(f"[WARNING] Could not get key grants: {e}")
        config["grants"] = []
    
    # 6. Get key tags
    try:
        print("[DEBUG] Fetching KMS key tags...")
        tags_response = kms_client.list_resource_tags(KeyId=key_id)
        config["tags"] = tags_response.get('Tags', [])
        print(f"[DEBUG] >> Number of tags: {len(config['tags'])}")
    except ClientError as e:
        print(f"[WARNING] Could not get key tags: {e}")
        config["tags"] = []
    
    # 7. Get replica keys (for multi-region keys)
    if config["multi_region"]:
        try:
            print("[DEBUG] Fetching replica keys for multi-region key...")
            replicas_response = kms_client.describe_key(KeyId=key_id)
            replica_keys = replicas_response.get('KeyMetadata', {}).get('MultiRegionConfiguration', {}).get('ReplicaKeys', [])
            config["replica_keys"] = [
                {
                    "key_id": replica.get('KeyId'),
                    "region": replica.get('Region')
                }
                for replica in replica_keys
            ]
            print(f"[DEBUG] >> Number of replica keys: {len(config['replica_keys'])}")
        except ClientError as e:
            print(f"[WARNING] Could not get replica keys: {e}")
            config["replica_keys"] = []
    
    return config

def audit_kms_key_security(key_id, account_id, region, kms_client=None):
    """
    Performs comprehensive KMS key security audit, queries OPA, and formats a Security Hub finding.
    
    Args:
        key_id: KMS key ID or ARN
        account_id: AWS account ID
        region: AWS region
        kms_client: Optional boto3 KMS client
        
    Returns:
        Security Hub finding dictionary or None if no issues found
    """
    print("\n" + "="*50) # New entry separator
    print(f"[INFO] Starting comprehensive KMS security audit for key: '{key_id}' in region '{region}'")

    if kms_client is None:
        kms_client = boto3.client('kms', region_name=region)

    # --- 1. Collect comprehensive KMS security configuration ---
    print("[DEBUG] Step 1: Collecting comprehensive KMS security configuration...")
    try:
        kms_config = get_kms_key_security_config(key_id, kms_client)
        if kms_config is None:
            print(f"[ERROR] Could not collect KMS configuration for key '{key_id}'.")
            return None
            
        print(f"[DEBUG] >> Successfully collected KMS security configuration")
        print(f"[DEBUG] >> Configuration summary: {json.dumps(kms_config, indent=2, default=str)}")
    except Exception as e:
        print(f"[ERROR] !! FAILED at Step 1. Could not collect KMS security configuration for key '{key_id}'. Reason: {e}")
        return None

    # --- 2. Query OPA with comprehensive configuration ---
    print("[DEBUG] Step 2: Querying KMS OPA with comprehensive configuration...")
    response_data = send_kms_opa_request(kms_config)
    if response_data is None:
        print(f"[ERROR] !! FAILED at Step 2. KMS OPA request failed for key '{key_id}'.")
        return None

    # --- 3. Parse the OPA result ---
    print("[DEBUG] Step 3: Parsing KMS OPA response...")
    finding_details = parse_kms_opa_response(response_data)
    if finding_details is None:
        print(f"[INFO] No KMS findings for key '{key_id}'. It is compliant.")
        print("="*50 + "\n")
        return None
    
    risk = finding_details["risk_level"]
    reason = finding_details["reason"]

    # --- 4. Generate comprehensive KMS finding ---
    print("[DEBUG] Step 4: Generating comprehensive KMS security finding...")
    
    finding_id_source = f"{account_id}{region}{key_id}{OPERATION}"
    finding_id = calculate_md5(finding_id_source)
    finding_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    
    # Create detailed description with KMS security configuration summary
    security_summary = []
    if not kms_config.get("key_rotation_enabled"):
        security_summary.append("Key rotation disabled")
    
    if kms_config.get("key_state") != "Enabled":
        security_summary.append(f"Key state: {kms_config.get('key_state')}")
    
    if kms_config.get("origin") != "AWS_KMS":
        security_summary.append(f"External key material: {kms_config.get('origin')}")
    
    if not kms_config.get("key_policy"):
        security_summary.append("No key policy")
    
    if len(kms_config.get("grants", [])) > 0:
        security_summary.append(f"{len(kms_config.get('grants', []))} active grants")
    
    description = f"KMS key '{key_id}' has security configuration issues. "
    if security_summary:
        description += f"Issues found: {', '.join(security_summary)}. "
    description += f"Policy evaluation reason: {reason}"
    
    finding = {
        "Findings": [
            {
                "SchemaVersion": "2018-10-08",
                "Id": f"arn:aws:kms:{region}:{account_id}:key/{key_id}/{OPERATION}",
                "ProductArn": f"arn:aws:securityhub:{region}::{account_id}:product/{account_id}/default",
                "GeneratorId": "cspm-kms-security-audit",
                "AwsAccountId": account_id,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "CreatedAt": finding_timestamp,
                "UpdatedAt": finding_timestamp,
                "Severity": normalize_severity(risk),
                "Title": "KMS Key Security Configuration Issues Detected",
                "Description": description,
                "Resources": [
                    {
                        "Type": "AwsKmsKey",
                        "Id": kms_config.get("key_arn", f"arn:aws:kms:{region}:{account_id}:key/{key_id}"),
                        "Partition": "aws",
                        "Region": region,
                        "Details": {
                            "AwsKmsKey": {
                                "KeyId": key_id,
                                "KeyState": kms_config.get("key_state"),
                                "KeyUsage": kms_config.get("key_usage"),
                                "KeySpec": kms_config.get("key_spec"),
                                "Origin": kms_config.get("origin"),
                                "KeyManager": kms_config.get("key_manager"),
                                "KeyRotationEnabled": kms_config.get("key_rotation_enabled"),
                                "MultiRegion": kms_config.get("multi_region"),
                                "Aliases": kms_config.get("aliases", []),
                                "GrantsCount": len(kms_config.get("grants", [])),
                                "TagsCount": len(kms_config.get("tags", []))
                            }
                        }
                    }
                ],
                "RecordState": "ACTIVE",
                "WorkflowState": "NEW",
                "Compliance": {
                    "Status": "FAILED",
                    "SecurityControlId": "KMS.1",
                    "AssociatedStandards": [
                        {
                            "StandardsId": "aws-foundational-security-standard"
                        }
                    ]
                },
                "UserDefinedFields": {
                    "KMSConfiguration": json.dumps(kms_config, default=str),
                    "FindingId": finding_id
                }
            }
        ]
    }
    
    print(f"[INFO] Successfully generated comprehensive KMS security finding for key '{key_id}'.")
    print("[DEBUG] Final KMS Finding Object:")
    print(json.dumps(finding, indent=2, default=str))
    print("="*50 + "\n")
    return finding