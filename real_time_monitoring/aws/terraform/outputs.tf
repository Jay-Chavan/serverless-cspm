output "ec2_public_ip" {
    value = module.ec2_module_opa_server.public_ip
  
}

output "lambda_arn" {
    value = module.lambda_module.lambda_function_arns
  
}

# Outputs for Lambda Auditors Module
output "kms_lambda_function_name" {
  description = "Name of the KMS Lambda function"
  value       = module.lambda_auditors_module.kms_lambda_function_name
}

output "kms_lambda_function_arn" {
  description = "ARN of the KMS Lambda function"
  value       = module.lambda_auditors_module.kms_lambda_function_arn
}

output "s3_lambda_function_name" {
  description = "Name of the S3 Lambda function"
  value       = module.lambda_auditors_module.s3_lambda_function_name
}

output "s3_lambda_function_arn" {
  description = "ARN of the S3 Lambda function"
  value       = module.lambda_auditors_module.s3_lambda_function_arn
}

output "kms_api_gateway_url" {
  description = "URL of the KMS API Gateway for S3 Lambda to call"
  value       = module.lambda_auditors_module.kms_api_gateway_url
}

output "kms_api_gateway_id" {
  description = "ID of the KMS API Gateway"
  value       = module.lambda_auditors_module.kms_api_gateway_id
}

# Outputs for EventBridge Module
output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for S3 bucket creation"
  value       = module.eventbridge_module.eventbridge_rule_arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule"
  value       = module.eventbridge_module.eventbridge_rule_name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail for S3 API monitoring"
  value       = module.eventbridge_module.cloudtrail_arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket storing CloudTrail logs"
  value       = module.eventbridge_module.cloudtrail_bucket_name
}