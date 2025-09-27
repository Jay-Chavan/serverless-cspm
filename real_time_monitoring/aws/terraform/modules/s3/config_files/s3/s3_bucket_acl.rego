package aws.s3_creation

default deny := false

# Rule when no Confidentiality tag is present
deny := {
    "risk_level": risk,
    "reason": "S3 bucket is public and missing adequate confidentiality context"
} if {
    input.resource_type == "s3"
    not is_bucket_owner_enforced(input.bucket_config)
    not has_confidentiality_tag(input.bucket_config.tagset)

    risk := "Critical (Unknown – No Confidentiality tag found)"
}

# Rule when Confidentiality tag is present
deny := {
    "risk_level": risk,
    "reason": reason
} if {
    input.resource_type == "s3"
    not is_bucket_owner_enforced(input.bucket_config)
    has_confidentiality_tag(input.bucket_config.tagset)

    risk := get_confidentiality_risk(input.bucket_config.tagset)
    reason := sprintf("S3 bucket is public and confidentiality tag includes: %v", [risk])
}

# Helper: bucket is owner enforced
is_bucket_owner_enforced(config) if {
    config.ownership.bucket_owner_enforced == true
}

# Helper: check if Confidentiality tag is present
has_confidentiality_tag(tags) if {
    some i
    tags[i].Key == "Confidentiality"
}

# Get mapped Confidentiality value or fallback to Critical
get_confidentiality_risk(tags) = level if {
    some i
    tags[i].Key == "Confidentiality"
    val := lower(tags[i].Value)

    level := {
        "high": "Critical",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "public": "Public"
    }[val]
} else = "Critical (Unknown – Unrecognized Confidentiality score)"
