output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for S3 bucket creation"
  value       = aws_cloudwatch_event_rule.s3_bucket_creation.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.s3_bucket_creation.name
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail for S3 API monitoring"
  value       = aws_cloudtrail.s3_api_trail.arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_bucket.bucket
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue for S3 audit events"
  value       = aws_sqs_queue.s3_audit_queue.arn
}

output "sqs_queue_url" {
  description = "URL of the SQS queue for S3 audit events"
  value       = aws_sqs_queue.s3_audit_queue.id
}

output "sqs_queue_name" {
  description = "Name of the SQS queue for S3 audit events"
  value       = aws_sqs_queue.s3_audit_queue.name
}