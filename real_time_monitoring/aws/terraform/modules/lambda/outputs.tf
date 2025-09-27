output "lambda_function_arns" {
  description = "ARNs of all created Lambda functions"
  value = {
    for name, lambda in aws_lambda_function.s3findings_lambda_function :
    name => lambda.arn
  }
}