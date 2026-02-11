package aws.s3_creation

default deny := false

# Main Rule: Flag if bucket is effectively public or has risky configuration
deny[{"risk_level": risk, "reason": reason}] {
    input.resource_type == "s3"
    is_publicly_accessible(input.bucket_config)
    risk := "High"
    reason := "S3 Bucket Public Access Enabled (PublicAccessBlock is off)"
}

# Helper: Check if bucket is publicly accessible
is_publicly_accessible(config) {
    # 1. Check if Public Access Block is NOT fully enabled
    config.public_access_block.status != "blocked"
    
    # And one of the following is true:
    # - ACLs are enabled (risk of individual object exposure)
    # - OR Policy is present (risk of public policy - complex to parse in Rego without more data, so we flag as risk if PAB is off)
    # For now, if PAB is off, we consider it a risk.
}

# Allow if explicitly marked private via tags (optional override)
allow {
    input.bucket_config.tagset[_].Key == "Classification"
    input.bucket_config.tagset[_].Value == "Private"
}
