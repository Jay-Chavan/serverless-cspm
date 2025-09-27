# variable "s3_findings_role_name" {

  
# }

variable "s3_bucket_name" {

  
}

variable "lambda_handler" {
    type = string
    default = "lambda_function.lambda_handler"

  
}

variable "runtime" {
    type = string
    default = "python3.9"
  
}

# variable "s3_bucket_name" {
#     default = "serverlesscspmbucketcloudc2"
# }

variable "s3_key_lambda_functions" {
    type = map(string)
    default = { 
        "s3finding_lambda_function" = "s3/lambda_function.zip", 
        "rds_lambda_function" = "RDS/lambda_function.zip"
    }
    
}


variable "account_id" {
    type = string
    default = "554739427981"
  
}

variable "ec2_public_ip" {
  
}
