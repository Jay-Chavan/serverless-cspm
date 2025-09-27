output "kms_lambda_function_name" {
  description = "Name of the KMS Lambda function"
  value       = aws_lambda_function.kms_auditor_lambda.function_name
}

output "kms_lambda_function_arn" {
  description = "ARN of the KMS Lambda function"
  value       = aws_lambda_function.kms_auditor_lambda.arn
}

output "s3_lambda_function_name" {
  description = "Name of the S3 Lambda function"
  value       = aws_lambda_function.s3_auditor_lambda.function_name
}

output "s3_lambda_function_arn" {
  description = "ARN of the S3 Lambda function"
  value       = aws_lambda_function.s3_auditor_lambda.arn
}

output "kms_api_gateway_url" {
  description = "URL of the KMS API Gateway"
  value       = aws_api_gateway_stage.kms_api_stage.invoke_url
}

output "kms_api_gateway_id" {
  description = "ID of the KMS API Gateway"
  value       = aws_api_gateway_rest_api.kms_api.id
}

output "kms_lambda_role_arn" {
  description = "ARN of the KMS Lambda IAM role"
  value       = aws_iam_role.kms_lambda_role.arn
}

output "s3_lambda_role_arn" {
  description = "ARN of the S3 Lambda IAM role"
  value       = aws_iam_role.s3_lambda_role.arn
}